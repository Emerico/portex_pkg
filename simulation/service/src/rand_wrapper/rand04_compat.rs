//#![no_std]

use core::marker::PhantomData;

use rand::Rng;
pub use rand04;

#[derive(Debug)]
pub struct Generator<'a, T, R>(&'a mut R, PhantomData<T>);

impl<'a, R: Rng, T: rand04::Rand> Iterator for Generator<'a, T, R> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        Some(self.0.gen04())
    }
}

/// An extension trait for `Rng` to generate values that implement `rand04::Rand`.
pub trait RngExt {
    /// Returns a random value.
    fn gen04<T: rand04::Rand>(&mut self) -> T;

    /// Returns an iterator that will yield an infinite number of randomly generated items.
    fn gen_iter04<T: rand04::Rand>(&mut self) -> Generator<T, Self>
    where
        Self: Sized;
}

impl<R: Rng + ?Sized> RngExt for R {
    fn gen04<T: rand04::Rand>(&mut self) -> T {
        rand04::Rng::gen(&mut RngWrapper(self))
    }

    fn gen_iter04<T: rand04::Rand>(&mut self) -> Generator<T, Self>
    where
        Self: Sized,
    {
        Generator(self, PhantomData)
    }
}

/// A wrapper for a random number generator that implements the 0.4 `Rng` trait.
pub struct RngWrapper<R>(pub R);

impl<R: Rng> rand04::Rng for RngWrapper<R> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
}
