use capnp::message::{Builder, HeapAllocator, Reader, ReaderOptions};
use capnp::serialize::{OwnedSegments, SEGMENTS_COUNT_LIMIT, SegmentLengthsBuilder};
use capnp::{Error, ErrorKind};
use compio::BufResult;
use compio::buf::{IntoInner, IoBuf, IoBufMut, SetLen};
use compio::io::{AsyncRead, AsyncReadExt};
use std::mem::MaybeUninit;
use std::rc::Rc;

pub(crate) type OutMessage = Rc<Builder<HeapAllocator>>;

const WORD: usize = 8;
const SPARE_BUDGET: usize = 2 * 1024 * 1024;

pub(crate) struct SegmentRef {
    _message: OutMessage,
    ptr: *const u8,
    len: usize,
}

impl IoBuf for SegmentRef {
    fn as_init(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

pub(crate) enum Chunk {
    Inline(Vec<u8>),
    Segment(SegmentRef),
}

impl IoBuf for Chunk {
    fn as_init(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes,
            Self::Segment(segment) => segment.as_init(),
        }
    }
}

pub(crate) struct Batch {
    chunks: Vec<Chunk>,
    spare: Vec<Vec<u8>>,
    spare_bytes: usize,
    inline_limit: usize,
    bytes: usize,
}

impl Batch {
    pub(crate) fn new(inline_limit: usize) -> Self {
        Self {
            chunks: Vec::new(),
            spare: Vec::new(),
            spare_bytes: 0,
            inline_limit,
            bytes: 0,
        }
    }

    pub(crate) fn push(&mut self, message: &OutMessage) {
        let segments = message.get_segments_for_output();
        let table = self.inline_tail();
        table.extend_from_slice(&(segments.len() as u32 - 1).to_le_bytes());
        for segment in segments.iter() {
            table.extend_from_slice(&((segment.len() / WORD) as u32).to_le_bytes());
        }
        if segments.len().is_multiple_of(2) {
            table.extend_from_slice(&[0; 4]);
        }
        self.bytes += (4 * (segments.len() + 1)).next_multiple_of(WORD);

        for segment in segments.iter() {
            if <[u8]>::is_empty(segment) {
                continue;
            }
            if segment.len() <= self.inline_limit {
                self.inline_tail().extend_from_slice(segment);
            } else {
                self.chunks.push(Chunk::Segment(SegmentRef {
                    _message: message.clone(),
                    ptr: segment.as_ptr(),
                    len: segment.len(),
                }));
            }
            self.bytes += segment.len();
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub(crate) fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    pub(crate) fn byte_count(&self) -> usize {
        self.bytes
    }

    pub(crate) fn take(&mut self) -> Vec<Chunk> {
        self.bytes = 0;
        std::mem::take(&mut self.chunks)
    }

    pub(crate) fn recycle(&mut self, mut chunks: Vec<Chunk>) {
        for chunk in chunks.drain(..) {
            if let Chunk::Inline(mut bytes) = chunk
                && self.spare_bytes + bytes.capacity() <= SPARE_BUDGET
            {
                bytes.clear();
                self.spare_bytes += bytes.capacity();
                self.spare.push(bytes);
            }
        }
        self.chunks = chunks;
    }

    fn inline_tail(&mut self) -> &mut Vec<u8> {
        if !matches!(self.chunks.last(), Some(Chunk::Inline(_))) {
            let bytes = match self.spare.pop() {
                Some(bytes) => {
                    self.spare_bytes -= bytes.capacity();
                    bytes
                }
                None => Vec::new(),
            };
            self.chunks.push(Chunk::Inline(bytes));
        }
        match self.chunks.last_mut() {
            Some(Chunk::Inline(bytes)) => bytes,
            _ => unreachable!(),
        }
    }
}

pub(crate) struct Inbound {
    staging: Vec<u8>,
    pos: usize,
    capacity: usize,
    options: ReaderOptions,
}

impl Inbound {
    pub(crate) fn new(options: ReaderOptions, capacity: usize) -> Self {
        Self {
            staging: Vec::with_capacity(capacity),
            pos: 0,
            capacity,
            options,
        }
    }

    pub(crate) async fn next<R: AsyncRead>(
        &mut self,
        reader: &mut R,
    ) -> capnp::Result<Option<Reader<OwnedSegments>>> {
        if !self.fill(reader, WORD, true).await? {
            return Ok(None);
        }
        let count = self.word_at(0).wrapping_add(1) as usize;
        if count == 0 || count >= SEGMENTS_COUNT_LIMIT {
            return Err(Error::from_kind(ErrorKind::InvalidNumberOfSegments(count)));
        }
        let table_len = (4 * (count + 1)).next_multiple_of(WORD);
        self.fill(reader, table_len, false).await?;

        let mut lengths = SegmentLengthsBuilder::with_capacity(count);
        for index in 0..count {
            lengths.try_push_segment(self.word_at(index + 1) as usize)?;
        }
        if let Some(limit) = self.options.traversal_limit_in_words
            && lengths.total_words() > limit
        {
            return Err(Error::from_kind(ErrorKind::MessageTooLarge(
                lengths.total_words(),
            )));
        }
        self.pos += table_len;

        let body_len = lengths.total_words() * WORD;
        let mut segments = lengths.into_owned_segments();
        if body_len <= self.capacity {
            self.fill(reader, body_len, false).await?;
            segments.copy_from_slice(&self.staging[self.pos..self.pos + body_len]);
            self.pos += body_len;
        } else {
            let buffered = (self.staging.len() - self.pos).min(body_len);
            segments[..buffered].copy_from_slice(&self.staging[self.pos..self.pos + buffered]);
            self.pos += buffered;
            let body = Body {
                segments,
                filled: buffered,
            };
            let BufResult(result, body) = reader
                .read_exact(body.slice(buffered..))
                .await
                .map_buffer(IntoInner::into_inner);
            result?;
            segments = body.segments;
        }
        Ok(Some(Reader::new(segments, self.options)))
    }

    async fn fill<R: AsyncRead>(
        &mut self,
        reader: &mut R,
        needed: usize,
        eof_ok: bool,
    ) -> capnp::Result<bool> {
        while self.staging.len() - self.pos < needed {
            if self.pos > 0 {
                self.staging.drain(..self.pos);
                self.pos = 0;
            }
            let wanted = self.capacity.max(needed);
            if self.staging.capacity() < wanted {
                self.staging.reserve_exact(wanted - self.staging.len());
            }
            let BufResult(result, staging) = reader.append(std::mem::take(&mut self.staging)).await;
            self.staging = staging;
            if result? == 0 {
                if eof_ok && self.staging.is_empty() {
                    return Ok(false);
                }
                return Err(Error::from_kind(ErrorKind::PrematureEndOfFile));
            }
        }
        Ok(true)
    }

    fn word_at(&self, index: usize) -> u32 {
        let at = self.pos + index * 4;
        let mut word = [0; 4];
        word.copy_from_slice(&self.staging[at..at + 4]);
        u32::from_le_bytes(word)
    }
}

struct Body {
    segments: OwnedSegments,
    filled: usize,
}

impl IoBuf for Body {
    fn as_init(&self) -> &[u8] {
        &self.segments[..self.filled]
    }
}

impl SetLen for Body {
    unsafe fn set_len(&mut self, len: usize) {
        self.filled = len;
    }
}

impl IoBufMut for Body {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let bytes: &mut [u8] = &mut self.segments;
        unsafe { &mut *(bytes as *mut [u8] as *mut [MaybeUninit<u8>]) }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod check {
    use super::*;
    use capnp::message::ReaderSegments;

    pub(crate) type Outcome = (Vec<Vec<Vec<u8>>>, Result<(), ErrorKind>);

    pub(crate) struct Trickle {
        data: Vec<u8>,
        pos: usize,
        steps: Vec<usize>,
        step: usize,
    }

    impl Trickle {
        pub(crate) fn new(data: Vec<u8>, steps: Vec<usize>) -> Self {
            Self {
                data,
                pos: 0,
                steps,
                step: 0,
            }
        }
    }

    impl AsyncRead for Trickle {
        async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
            let step = self
                .steps
                .get(self.step % self.steps.len().max(1))
                .copied()
                .unwrap_or(usize::MAX)
                .max(1);
            self.step += 1;
            let source = &self.data[self.pos..];
            let target = buf.as_uninit();
            let n = step.min(target.len()).min(source.len());
            for (to, from) in target.iter_mut().zip(&source[..n]) {
                to.write(*from);
            }
            self.pos += n;
            unsafe { buf.advance_to(n) };
            BufResult(Ok(n), buf)
        }
    }

    pub(crate) fn segments(message: Reader<OwnedSegments>) -> Vec<Vec<u8>> {
        let segments = message.into_segments();
        (0..segments.len())
            .filter_map(|id| segments.get_segment(id as u32))
            .map(<[u8]>::to_vec)
            .collect()
    }

    pub(crate) fn ours(
        stream: &[u8],
        steps: &[usize],
        capacity: usize,
        options: ReaderOptions,
    ) -> Outcome {
        let mut reader = Trickle::new(stream.to_vec(), steps.to_vec());
        let mut inbound = Inbound::new(options, capacity);
        let mut messages = Vec::new();
        futures::executor::block_on(async {
            loop {
                match inbound.next(&mut reader).await {
                    Ok(Some(message)) => messages.push(segments(message)),
                    Ok(None) => return (messages, Ok(())),
                    Err(error) => return (messages, Err(error.kind)),
                }
            }
        })
    }

    pub(crate) fn stock(stream: &[u8], options: ReaderOptions) -> Outcome {
        let mut rest = stream;
        let mut messages = Vec::new();
        loop {
            match capnp::serialize::try_read_message(&mut rest, options) {
                Ok(Some(message)) => messages.push(segments(message)),
                Ok(None) => return (messages, Ok(())),
                Err(error) if error.kind == ErrorKind::FailedToFillTheWholeBuffer => {
                    return (messages, Err(ErrorKind::PrematureEndOfFile));
                }
                Err(error) => return (messages, Err(error.kind)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::check::{Trickle, segments as read_segments};
    use super::*;
    use capnp::message::AllocationStrategy;
    use futures::executor::block_on;
    use proptest::prelude::*;

    type Spec = Vec<(u32, Vec<Vec<u8>>)>;

    fn specs() -> impl Strategy<Value = Spec> {
        prop::collection::vec(
            (
                1u32..24,
                prop::collection::vec(prop::collection::vec(any::<u8>(), 0..700), 0..6),
            ),
            1..6,
        )
    }

    fn steps() -> impl Strategy<Value = Vec<usize>> {
        prop::collection::vec(1usize..400, 1..8)
    }

    fn build(spec: &Spec) -> Vec<OutMessage> {
        spec.iter()
            .map(|(first_segment_words, blobs)| {
                let mut message = Builder::new(
                    HeapAllocator::new()
                        .first_segment_words(*first_segment_words)
                        .allocation_strategy(AllocationStrategy::FixedSize),
                );
                let mut list = message.initn_root::<capnp::data_list::Builder>(blobs.len() as u32);
                for (index, blob) in blobs.iter().enumerate() {
                    list.set(index as u32, blob);
                }
                Rc::new(message)
            })
            .collect()
    }

    fn stock_bytes(messages: &[OutMessage]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for message in messages {
            capnp::serialize::write_message(&mut bytes, &**message).unwrap();
        }
        bytes
    }

    fn written_segments(message: &OutMessage) -> Vec<Vec<u8>> {
        message
            .get_segments_for_output()
            .iter()
            .map(|segment| segment.to_vec())
            .collect()
    }

    fn concat(chunks: &[Chunk]) -> Vec<u8> {
        chunks.iter().flat_map(|chunk| chunk.as_init().to_vec()).collect()
    }

    proptest! {
        #[test]
        fn a_batch_is_byte_for_byte_what_capnp_serialize_writes(
            spec in specs(),
            inline_limit in 0usize..2048,
        ) {
            let messages = build(&spec);
            let expected = stock_bytes(&messages);
            let mut batch = Batch::new(inline_limit);

            for _round in 0..2 {
                for message in &messages {
                    batch.push(message);
                }
                prop_assert_eq!(batch.byte_count(), expected.len());
                let chunks = batch.take();
                prop_assert!(chunks.iter().all(|chunk| !chunk.as_init().is_empty()));
                let only_large_segments_by_reference = chunks.iter().all(|chunk| match chunk {
                    Chunk::Segment(segment) => segment.len > inline_limit,
                    Chunk::Inline(_) => true,
                });
                prop_assert!(only_large_segments_by_reference);
                prop_assert_eq!(concat(&chunks), expected.clone());
                batch.recycle(chunks);
            }
        }

        #[test]
        fn inbound_reads_back_what_capnp_serialize_wrote(
            spec in specs(),
            steps in steps(),
            capacity in 8usize..2048,
        ) {
            let messages = build(&spec);
            let mut reader = Trickle::new(stock_bytes(&messages), steps);
            let mut inbound = Inbound::new(ReaderOptions::new(), capacity);
            block_on(async {
                for message in &messages {
                    let read = inbound.next(&mut reader).await.unwrap();
                    prop_assert_eq!(read.map(read_segments), Some(written_segments(message)));
                }
                prop_assert!(inbound.next(&mut reader).await.unwrap().is_none());
                Ok(())
            })?;
        }

        #[test]
        fn inbound_reads_back_what_a_batch_wrote(
            spec in specs(),
            inline_limit in 0usize..2048,
            steps in steps(),
            capacity in 8usize..2048,
        ) {
            let messages = build(&spec);
            let mut batch = Batch::new(inline_limit);
            for message in &messages {
                batch.push(message);
            }
            let mut reader = Trickle::new(concat(&batch.take()), steps);
            let mut inbound = Inbound::new(ReaderOptions::new(), capacity);
            block_on(async {
                for message in &messages {
                    let read = inbound.next(&mut reader).await.unwrap();
                    prop_assert_eq!(read.map(read_segments), Some(written_segments(message)));
                }
                prop_assert!(inbound.next(&mut reader).await.unwrap().is_none());
                Ok(())
            })?;
        }

        #[test]
        fn a_stream_cut_inside_a_message_fails_and_on_a_boundary_ends(
            spec in specs(),
            steps in steps(),
            capacity in 8usize..2048,
            cut in any::<prop::sample::Index>(),
        ) {
            let messages = build(&spec);
            let bytes = stock_bytes(&messages);
            let mut boundaries = vec![0];
            for message in &messages {
                let words = capnp::serialize::compute_serialized_size_in_words(&**message);
                boundaries.push(boundaries.last().unwrap() + words * WORD);
            }
            let cut = cut.index(bytes.len() + 1);
            let complete = boundaries.iter().filter(|&&boundary| boundary <= cut).count() - 1;

            let mut reader = Trickle::new(bytes[..cut].to_vec(), steps);
            let mut inbound = Inbound::new(ReaderOptions::new(), capacity);
            block_on(async {
                for message in &messages[..complete] {
                    let read = inbound.next(&mut reader).await.unwrap();
                    prop_assert_eq!(read.map(read_segments), Some(written_segments(message)));
                }
                let end = inbound.next(&mut reader).await;
                if boundaries.contains(&cut) {
                    prop_assert!(matches!(end, Ok(None)));
                } else {
                    prop_assert!(matches!(end, Err(ref e) if e.kind == ErrorKind::PrematureEndOfFile));
                }
                Ok(())
            })?;
        }

        #[test]
        fn inbound_accepts_exactly_what_capnp_accepts(
            count_field in prop_oneof![0u32..6, 509u32..514, Just(u32::MAX)],
            lengths in prop::collection::vec(prop_oneof![0u32..40, Just(1 << 20), Just(u32::MAX)], 0..8),
            body in prop::collection::vec(any::<u8>(), 0..700),
            valid_first in any::<bool>(),
            spec in specs(),
            limit in 0usize..3000,
            steps in steps(),
            capacity in 0usize..2048,
        ) {
            let mut arbitrary = count_field.to_le_bytes().to_vec();
            for length in &lengths {
                arbitrary.extend_from_slice(&length.to_le_bytes());
            }
            arbitrary.extend_from_slice(&body);
            let valid = stock_bytes(&build(&spec));
            let bytes = if valid_first {
                [valid, arbitrary].concat()
            } else {
                [arbitrary, valid].concat()
            };
            let mut options = ReaderOptions::new();
            options.traversal_limit_in_words(Some(limit));

            prop_assert_eq!(
                super::check::ours(&bytes, &steps, capacity, options),
                super::check::stock(&bytes, options)
            );
        }
    }
}
