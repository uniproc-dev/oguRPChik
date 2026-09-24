#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    capacity: u16,
    limit: u16,
    steps: Vec<u16>,
    stream: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let steps: Vec<usize> = input.steps.iter().take(16).map(|&step| step as usize).collect();
    ogurpchik::rpc::fuzzing::inbound_matches_stock(
        &input.stream,
        &steps,
        input.capacity as usize,
        input.limit as usize,
    );
});
