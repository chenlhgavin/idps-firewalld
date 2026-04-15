#![no_std]
#![no_main]

mod egress;
mod identity;
mod ingress;
mod maps;
mod packet;
mod rules;
mod stats;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
