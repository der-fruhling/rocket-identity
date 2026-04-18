use std::borrow::Borrow;
use std::collections::{BTreeSet, HashSet};
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;

pub trait Scope<S: ?Sized>: 'static {
    fn test(value: &S) -> bool;
    fn fmt(f: &mut Formatter) -> std::fmt::Result;

    fn display() -> impl Display {
        struct DisplayImpl<S: ?Sized, Sc: Scope<S> + ?Sized>(PhantomData<(*const Sc, S)>);

        impl<S: ?Sized, Sc: Scope<S> + ?Sized> Display for DisplayImpl<S, Sc> {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                <Sc as Scope<S>>::fmt(f)
            }
        }

        DisplayImpl::<S, Self>(PhantomData)
    }
}

#[doc(hidden)]
#[non_exhaustive]
pub struct AnyOf<T>(T);

#[doc(hidden)]
#[non_exhaustive]
pub struct AllOf<T>(T);

#[doc(hidden)]
#[non_exhaustive]
pub struct Not<T>(T);

impl<S: ?Sized, T: Scope<S>> Scope<S> for Not<T> {
    #[inline(always)]
    fn test(value: &S) -> bool {
        !T::test(value)
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        f.write_char('!')?;
        T::fmt(f)
    }
}

#[doc(hidden)]
#[derive(Default)]
pub struct Const<const VALUE: bool>;

impl<S: ?Sized, const VALUE: bool> Scope<S> for Const<VALUE> {
    fn test(_: &S) -> bool {
        VALUE
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(&VALUE, f)
    }
}

#[doc(hidden)]
#[non_exhaustive]
pub struct Compose<T, Def = Const<false>>(T, Def);

macro_rules! gen_fmt {
    ($name:ident($($p:ident),*)) => {
        #[allow(unused, unused_assignments)]
        fn fmt(f: &mut Formatter) -> std::fmt::Result {
            f.write_str(concat!(stringify!($name), "("))?;

            let mut comma = false;
            $(
            if comma { f.write_str(", ")?; }
            else { comma = true; }
            $p::fmt(f)?;
            )*

            f.write_char(')')
        }
    };
}

macro_rules! scope_array {
    ($(<$($p:ident),* $(,)?>;)*) => {
        #[allow(unused_parens, non_snake_case)]
        const _: () = {$(
            impl<S: ?Sized, $($p: Scope<S>),*> Scope<S> for ($($p,)*) where AllOf<($($p,)*)>: Scope<S> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    AllOf::<($($p,)*)>::test(value)
                }

                fn fmt(f: &mut Formatter) -> std::fmt::Result {
                    AllOf::<($($p,)*)>::fmt(f)
                }
            }

            impl<S: ?Sized, $($p: Scope<S>),*> Scope<S> for AllOf<($($p,)*)> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    $(<$p as Scope<S>>::test(value))&&*
                }

                gen_fmt!(all($($p),*));
            }

            impl<S: ?Sized, $($p: Scope<S>),*> Scope<S> for AnyOf<($($p,)*)> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    $(<$p as Scope<S>>::test(value))||*
                }

                gen_fmt!(any($($p),*));
            }
        )*};
    };
}

macro_rules! compose_array {
    ($(<$($p:ident if $c:ident),* $(,)?>;)*) => {
        #[allow(unused_parens)]
        const _: () = {$(
            impl<S: ?Sized, Def: Scope<S>, $($p: Scope<S>, $c: Scope<S>),*> Scope<S> for Compose<($(($c, $p),)*), Def> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    $(if <$c as Scope<S>>::test(value) {
                        return <$p as Scope<S>>::test(value);
                    })*

                    <Def as Scope<S>>::test(value)
                }

                fn fmt(f: &mut Formatter) -> std::fmt::Result {
                    f.write_str("compose { ")?;

                    let mut comma = false;
                    $(
                    if comma { f.write_str(", ")?; }
                    else { comma = true; }
                    $c::fmt(f)?;
                    f.write_str(" => ")?;
                    $p::fmt(f)?;
                    )*

                    if ::std::any::TypeId::of::<Def>() != ::std::any::TypeId::of::<Const<false>>() {
                        if comma { f.write_str(", ")?; }
                        f.write_str("_ => ")?;
                        Def::fmt(f)?;
                    }

                    f.write_str(" }")
                }
            }
        )*};
    };
}

scope_array! {
    <T1>;
    <T1, T2>;
    <T1, T2, T3>;
    <T1, T2, T3, T4>;
    <T1, T2, T3, T4, T5>;
    <T1, T2, T3, T4, T5, T6>;
    <T1, T2, T3, T4, T5, T6, T7>;
    <T1, T2, T3, T4, T5, T6, T7, T8>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20>;
}

compose_array! {
    <T1 if C1>;
    <T1 if C1, T2 if C2>;
    <T1 if C1, T2 if C2, T3 if C3>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17, T18 if C18>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17, T18 if C18, T19 if C19>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17, T18 if C18, T19 if C19, T20 if C20>;
}

#[macro_export]
macro_rules! allow {
    [] => { $crate::scope::Const::<true> };
    [$scope:ty] => { $scope };
    [!$scope:ty] => { $crate::not!($scope) };
    [true] => { $crate::scope::Const::<true> };
    [false] => { $crate::scope::Const::<false> };
}

#[macro_export]
macro_rules! any {
    ($($($scope:ty)*),+) => { $crate::scope::AnyOf::<($($crate::allow![$($scope)*],)*)> };
}

#[macro_export]
macro_rules! all {
    ($($($scope:ty)*),+) => { $crate::scope::AllOf::<($($crate::allow![$($scope)*],)*)> };
}

#[macro_export]
macro_rules! not {
    ($scope:ty) => {
        $crate::scope::Not::<$crate::allow![$scope]>
    };
}

#[macro_export]
macro_rules! compose {
    (_ => $scope:ty) => { $scope };
    ($condition:ty => $scope:ty) => { $crate::all!($condition, $scope) };
    ($($condition:ty => $scope:ty),* $(, $(@ => $default:ty)?)?) => {
        $crate::scope::Compose::<($(($condition, $scope),)*)$($(, $default)?)?>
    };
}

#[macro_export]
macro_rules! deny {
    [] => { $crate::scope::Const::<false> };
    ($($tt:tt)+) => { $crate::not!($crate::allow!($($tt)*)) };
}

pub trait ConstStr: 'static {
    const VALUE: &'static str;
}

impl<S: Borrow<str> + Eq + Hash, C: ConstStr> Scope<HashSet<S>> for C {
    #[inline(always)]
    fn test(value: &HashSet<S>) -> bool {
        value.contains(C::VALUE)
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

impl<S: Borrow<str> + Ord, C: ConstStr> Scope<BTreeSet<S>> for C {
    #[inline(always)]
    fn test(value: &BTreeSet<S>) -> bool {
        value.contains(C::VALUE)
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

impl<S: Borrow<str> + Eq, C: ConstStr> Scope<[S]> for C {
    #[inline(always)]
    fn test(value: &[S]) -> bool {
        for v in value {
            if v.borrow() == C::VALUE {
                return true;
            }
        }

        false
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

impl<S: Borrow<str> + Eq, C: ConstStr, const LEN: usize> Scope<[S; LEN]> for C {
    #[inline(always)]
    fn test(value: &[S; LEN]) -> bool {
        for v in value {
            if v.borrow() == C::VALUE {
                return true;
            }
        }

        false
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

#[macro_export]
macro_rules! const_str {
    {$($(#[$meta:meta])* $vis:vis type $name:ident = $value:expr;)*} => {$(
        $(#[$meta])*
        $vis enum $name {}

        impl $crate::scope::ConstStr for $name {
            const VALUE: &'static str = $value;
        }
    )*};
}
