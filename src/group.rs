/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::BigNumber;

use core::{
    borrow::Borrow,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// Represents a residual group where all operations are reduced by a modulus.
/// Purely a convenience struct to avoid having to call mod{ops}
#[derive(Debug, Clone)]
pub struct Group {
    /// The current value
    pub(crate) value: BigNumber,
    /// The upper limit that all values in the group are to be reduced
    pub(crate) modulus: BigNumber,
}

macro_rules! bin_ops_impl {
    ($trait:ident, $func:ident, $op:tt) => {
        impl $trait for Group {
            type Output = Group;

            fn $func(self, rhs: Group) -> Group {
                &self $op &rhs
            }
        }

        impl $trait<&Group> for Group {
            type Output = Group;

            fn $func(self, rhs: &Group) -> Group {
                &self $op rhs
            }
        }

        impl $trait<Group> for &Group {
            type Output = Group;

            fn $func(self, rhs: Group) -> Group {
                self $op &rhs
            }
        }
    };
}
macro_rules! bin_assign_ops_impl {
    ($trait:ident, $func:ident, $op:tt) => {
        impl $trait for Group {
            fn $func(&mut self, rhs: Group) {
                *self = &*self $op &rhs;
            }
        }

        impl $trait<&Group> for Group {
            fn $func(&mut self, rhs: &Group) {
                *self = &*self $op rhs;
            }
        }
    };
}

impl Add<&Group> for &Group {
    type Output = Group;

    fn add(self, rhs: &Group) -> Group {
        assert_eq!(self.modulus, rhs.modulus);
        Group {
            value: self.value.modadd(&rhs.value, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}
bin_ops_impl!(Add, add, +);
bin_assign_ops_impl!(AddAssign, add_assign, +);

impl Sub<&Group> for &Group {
    type Output = Group;

    fn sub(self, rhs: &Group) -> Group {
        assert_eq!(self.modulus, rhs.modulus);
        Group {
            value: self.value.modsub(&rhs.value, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}
bin_ops_impl!(Sub, sub, -);
bin_assign_ops_impl!(SubAssign, sub_assign, -);

impl Mul<&Group> for &Group {
    type Output = Group;

    fn mul(self, rhs: &Group) -> Group {
        assert_eq!(self.modulus, rhs.modulus);
        Group {
            value: self.value.modmul(&rhs.value, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}
bin_ops_impl!(Mul, mul, *);
bin_assign_ops_impl!(MulAssign, mul_assign, *);

impl Div<&Group> for &Group {
    type Output = Group;

    fn div(self, rhs: &Group) -> Group {
        assert_eq!(self.modulus, rhs.modulus);
        Group {
            value: self.value.moddiv(&rhs.value, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}
bin_ops_impl!(Div, div, /);
bin_assign_ops_impl!(DivAssign, div_assign, /);

impl Neg for &Group {
    type Output = Group;

    fn neg(self) -> Group {
        Group {
            value: self.value.modneg(&self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}

impl Neg for Group {
    type Output = Group;

    fn neg(self) -> Group {
        -&self
    }
}

impl<T> Sum<T> for Group
where
    T: Borrow<Group>,
{
    fn sum<I>(mut iter: I) -> Group
    where
        I: Iterator<Item = T>,
    {
        let mut r = if let Some(a) = iter.next() {
            a.borrow().clone()
        } else {
            return Group::zero(BigNumber::one());
        };
        for a in iter {
            let aa = a.borrow();
            assert_eq!(r.modulus, aa.modulus);
            r += a.borrow();
        }
        r
    }
}

impl<T> Product<T> for Group
where
    T: Borrow<Group>,
{
    fn product<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        let mut r = if let Some(a) = iter.next() {
            a.borrow().clone()
        } else {
            return Group::one(BigNumber::one());
        };
        for a in iter {
            let aa = a.borrow();
            assert_eq!(r.modulus, aa.modulus);
            r *= aa;
        }
        r
    }
}

impl Group {
    /// Create a new group where the given `modulus` must be odd.
    /// If not then the function returns [`None`]
    pub fn new(value: BigNumber, modulus: BigNumber) -> Option<Self> {
        if modulus.is_even() {
            return None;
        }
        Some(Self { value, modulus })
    }

    /// Create a new group. If `modulus` is odd then the function will panic.
    pub fn new_unchecked(value: BigNumber, modulus: BigNumber) -> Self {
        assert!(modulus.is_odd());
        Self { value, modulus }
    }

    /// Return the current value
    pub const fn value(&self) -> &BigNumber {
        &self.value
    }

    /// Return the modulus
    pub const fn modulus(&self) -> &BigNumber {
        &self.modulus
    }

    /// Compute the modular inverse of the current value if one exists
    pub fn invert(&self) -> Option<Group> {
        self.value.invert(&self.modulus).map(|value| Group {
            value,
            modulus: self.modulus.clone(),
        })
    }

    /// Compute the modular exponentiation of the current value
    /// raised to the power of `exponent`
    pub fn pow(&self, exponent: &BigNumber) -> Group {
        Group {
            value: self.value.modpow(exponent, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }

    /// Compute the modular square of the current value
    pub fn square(&self) -> Group {
        Group {
            value: self.value.modsqr(&self.modulus),
            modulus: self.modulus.clone(),
        }
    }

    /// Return the additive identity
    pub fn zero(modulus: BigNumber) -> Group {
        Group {
            value: BigNumber::zero(),
            modulus,
        }
    }

    /// Return the multiplicative identity
    pub fn one(modulus: BigNumber) -> Group {
        Group {
            value: BigNumber::one(),
            modulus,
        }
    }
}
