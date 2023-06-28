// Protocol Buffers - Google's data interchange format
// Copyright 2023 Google Inc.  All rights reserved.
// https://developers.google.com/protocol-buffers/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Items specific to `optional` fields.
#![allow(dead_code)]
#![allow(unused)]

use crate::__internal::Private;
use crate::{Mut, MutProxy, OptionalProxied, Proxied, SettableValue, View, ViewProxy};
use std::convert::{AsMut, AsRef};
use std::fmt::{self, Debug};
use std::panic;
use std::ptr;

/// A protobuf value from a field that may not be set.
///
/// This can be pattern matched with `match` or `if let` to determine if the
/// field is set and access the field data.
///
/// [`FieldEntry`], a specific type alias for `Optional`, provides much of the
/// functionality for this type.
///
/// Two `Optional`s are equal if they match both presence and the field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Optional<SetVal, UnsetVal = SetVal> {
    /// The field is present. It can be accessed through this `T`.
    ///
    /// - For an `_opt()` accessor, this contains a `View<impl Proxied>`.
    /// - For a `_mut()` accessor, this contains a [`PresentField`].
    Set(SetVal),

    /// The field is unset.
    ///
    /// - For an `_opt()` accessor, this contains a `View<impl Proxied>` with
    ///   the default value.
    /// - For a `_mut()` accessor, this contains an [`AbsentField`] that can be
    ///   used to access the default or set a new value.
    Unset(UnsetVal),
}

impl<T> Optional<T> {
    /// Gets the field value, ignoring whether it was set or not.
    pub fn into_inner(self) -> T {
        match self {
            Optional::Set(x) | Optional::Unset(x) => x,
        }
    }

    /// Constructs an `Optional<T>` with a `T` value and presence bit.
    pub fn new(val: T, is_set: bool) -> Self {
        if is_set { Optional::Set(val) } else { Optional::Unset(val) }
    }
}

impl<T, A> Optional<T, A> {
    /// Converts into an `Option` of the set value, ignoring any unset value.
    pub fn into_option(self) -> Option<T> {
        if let Optional::Set(x) = self { Some(x) } else { None }
    }

    /// Returns if the field is set.
    pub fn is_set(&self) -> bool {
        matches!(self, Optional::Set(_))
    }

    /// Returns if the field is unset.
    pub fn is_unset(&self) -> bool {
        matches!(self, Optional::Unset(_))
    }
}

impl<T> From<Optional<T>> for Option<T> {
    fn from(x: Optional<T>) -> Option<T> {
        x.into_option()
    }
}

/// A mutable view into the value of an optional field, which may be set or
/// unset.
pub type FieldEntry<'a, T> = Optional<PresentField<'a, T>, AbsentField<'a, T>>;

/// Methods for `_mut()` accessors of optional types.
///
/// The most common methods are [`set`] and [`or_default`].
impl<'msg, T: OptionalProxied + ?Sized + 'msg> FieldEntry<'msg, T> {
    // is_set() is provided by `impl<T, A> Optional<T, A>`

    /// Gets a mutator for this field. Sets to the default value if not set.
    pub fn or_default(self) -> Mut<'msg, T> {
        match self {
            Optional::Set(x) => x.into_mut(),
            Optional::Unset(x) => x.set_default().into_mut(),
        }
    }

    /// Sets the value of this field to `val`.
    ///
    /// Equivalent to `self.or_default().set(val)`.
    pub fn set(&mut self, val: impl SettableValue<T>) {
        transform_mut(self, |mut self_| match self_ {
            Optional::Set(ref mut present) => {
                present.set(val);
                self_
            }
            Optional::Unset(absent) => Optional::Set(absent.set(val)),
        })
    }

    /// Clears the field; `is_set()` will return `false`.
    pub fn clear(&mut self) {
        transform_mut(self, |self_| match self_ {
            Optional::Set(present) => Optional::Unset(present.clear()),
            absent => absent,
        })
    }

    /// Gets an immutable view of this field, using its default value if not
    /// set.
    ///
    /// This has a shorter lifetime than the `field_name()` message accessor;
    /// `into_view` provides that lifetime.
    pub fn get(self) -> View<'msg, T> {
        self.into_view()
    }
}

impl<'msg, T: OptionalProxied + ?Sized + 'msg> ViewProxy<'msg> for FieldEntry<'msg, T> {
    type Proxied = T;

    fn as_view(&self) -> View<'_, T> {
        match self {
            Optional::Set(x) => x.as_view(),
            Optional::Unset(x) => x.as_view(),
        }
    }

    fn into_view<'shorter>(self) -> View<'shorter, T>
    where
        'msg: 'shorter,
    {
        match self {
            Optional::Set(x) => x.into_view(),
            Optional::Unset(x) => x.into_view(),
        }
    }
}

// `MutProxy` not implemented for `FieldEntry` since the field may not be set,
// and `as_mut`/`into_mut` should not insert.

/// A field mutator capable of clearing that is statically known to point to a
/// set field.
pub struct PresentField<'msg, T>
where
    T: OptionalProxied + ?Sized + 'msg,
{
    inner: T::PresentMutData<'msg>,
}

impl<'msg, T: OptionalProxied + ?Sized + 'msg> Debug for PresentField<'msg, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<'msg, T: OptionalProxied + ?Sized + 'msg> PresentField<'msg, T> {
    #[doc(hidden)]
    pub fn from_inner(_private: Private, inner: T::PresentMutData<'msg>) -> Self {
        Self { inner }
    }

    pub fn get(self) -> View<'msg, T> {
        self.into_view()
    }

    pub fn set(&mut self, val: impl SettableValue<T>) {
        val.set_on(Private, self.as_mut())
    }

    /// See [`FieldEntry::clear`].
    pub fn clear(mut self) -> AbsentField<'msg, T> {
        AbsentField { inner: T::clear_present_field(self.inner) }
    }

    // This cannot provide `reborrow` - `clear` consumes after setting the field
    // because it would violate a condition of `PresentField` - the field being set.
}

impl<'msg, T> ViewProxy<'msg> for PresentField<'msg, T>
where
    T: OptionalProxied + ?Sized + 'msg,
{
    type Proxied = T;

    fn as_view(&self) -> View<'_, T> {
        self.inner.as_view()
    }

    fn into_view<'shorter>(self) -> View<'shorter, T>
    where
        'msg: 'shorter,
    {
        self.inner.into_view()
    }
}

impl<'msg, T> MutProxy<'msg> for PresentField<'msg, T>
where
    T: OptionalProxied + ?Sized + 'msg,
{
    fn as_mut(&mut self) -> Mut<'_, T> {
        self.inner.as_mut()
    }

    fn into_mut<'shorter>(self) -> Mut<'shorter, T>
    where
        'msg: 'shorter,
    {
        self.inner.into_mut()
    }
}

/// A field mutator capable of setting that is statically known to point to a
/// non-set field.
pub struct AbsentField<'a, T>
where
    T: OptionalProxied + ?Sized + 'a,
{
    inner: T::AbsentMutData<'a>,
}

impl<'msg, T: OptionalProxied + ?Sized + 'msg> Debug for AbsentField<'msg, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<'msg, T: OptionalProxied + ?Sized> AbsentField<'msg, T> {
    #[doc(hidden)]
    pub fn from_inner(_private: Private, inner: T::AbsentMutData<'msg>) -> Self {
        Self { inner }
    }

    /// Gets the default value for this unset field.
    ///
    /// This is the same value that the primitive accessor would provide.
    pub fn default_value(self) -> View<'msg, T> {
        self.into_view()
    }

    /// See [`FieldEntry::set`]. Note that this consumes and returns a
    /// `PresentField`.
    pub fn set(self, val: impl SettableValue<T>) -> PresentField<'msg, T> {
        PresentField { inner: val.set_on_absent(Private, self.inner) }
    }

    /// Sets this absent field to its default value.
    pub fn set_default(self) -> PresentField<'msg, T> {
        PresentField { inner: T::set_absent_to_default(self.inner) }
    }

    // This cannot provide `reborrow` - `set` consumes after setting the field
    // because it would violate a condition of `AbsentField` - the field being
    // unset.
}

impl<'msg, T> ViewProxy<'msg> for AbsentField<'msg, T>
where
    T: OptionalProxied + ?Sized + 'msg,
{
    type Proxied = T;

    fn as_view(&self) -> View<'_, T> {
        self.inner.as_view()
    }

    fn into_view<'shorter>(self) -> View<'shorter, T>
    where
        'msg: 'shorter,
    {
        self.inner.into_view()
    }
}

/// Transforms a mutable reference in-place, treating it as if it were owned.
///
/// The program will abort if `transform` panics.
///
/// This is the same operation as provided by [`take_mut::take`].
///
/// [`take_mut::take`]: https://docs.rs/take_mut/latest/take_mut/fn.take.html
fn transform_mut<T>(mut_ref: &mut T, transform: impl FnOnce(T) -> T) {
    #[cold]
    #[inline(never)]
    fn panicked_in_transform_mut() -> ! {
        use std::io::Write as _;
        let backtrace = std::backtrace::Backtrace::capture();
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        let _ = write!(&mut stderr, "BUG: A protobuf setter panicked! Backtrace:\n{backtrace}\n");
        let _ = stderr.flush();
        std::process::abort()
    }

    // https://play.rust-lang.org/?edition=2021&gist=f3014e1f209013f0a38352e211f4a240
    // provides a sample test to confirm this operation is sound in Miri.
    // SAFETY:
    // - `old_t` is not dropped without also replacing `*mut_ref`, preventing a
    //   double-free.
    // - If `transform` panics, the process aborts since `*mut_ref` has no possible
    //   valid value.
    // - After `ptr::write`, a valid `T` is located at `*mut_ref`
    unsafe {
        let p: *mut T = mut_ref;
        let old_t = p.read();
        let new_t = panic::catch_unwind(panic::AssertUnwindSafe(move || transform(old_t)))
            .unwrap_or_else(|_| panicked_in_transform_mut());
        p.write(new_t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    /// A sample message with custom presence bits, meant to mirror a C++
    /// message.
    #[derive(Default, Debug)]
    struct MyMessage {
        /// has a default of `0`
        a: i32,

        /// has a default of `5`
        b: i32,

        /// Packed presence bitfield for `a` and `b`
        presence: u8,
    }

    impl MyMessage {
        fn a(&self) -> View<'_, VtableProxied> {
            VtableProxiedView { val: get_a(self) }
        }

        fn a_opt(&self) -> Optional<View<'_, VtableProxied>> {
            Optional::new(self.a(), has_a(self))
        }

        fn a_mut(&mut self) -> FieldEntry<'_, VtableProxied> {
            static A_VTABLE: ProxyVtable =
                ProxyVtable { get: get_a, set: set_a, clear: clear_a, has: has_a };
            make_field_entry(self, &A_VTABLE)
        }

        fn b(&self) -> View<'_, VtableProxied> {
            VtableProxiedView { val: get_b(self) }
        }

        fn b_opt(&self) -> Optional<View<'_, VtableProxied>> {
            Optional::new(self.b(), has_b(self))
        }

        fn b_mut(&mut self) -> FieldEntry<'_, VtableProxied> {
            static B_VTABLE: ProxyVtable =
                ProxyVtable { get: get_b, set: set_b, clear: clear_b, has: has_b };
            make_field_entry(self, &B_VTABLE)
        }
    }

    fn make_field_entry<'a>(
        msg: &'a mut MyMessage,
        vtable: &'a ProxyVtable,
    ) -> FieldEntry<'a, VtableProxied> {
        if (vtable.has)(&*msg) {
            Optional::Set(PresentField::from_inner(
                Private,
                VtableProxiedMut { msg, vtable: vtable },
            ))
        } else {
            Optional::Unset(AbsentField::from_inner(
                Private,
                VtableProxiedMut { msg, vtable: vtable },
            ))
        }
    }

    // Thunks used for the vtable. For a C++ message these would be defined in C++
    // and exported via a C API
    const A_BIT: u8 = 0;
    const B_BIT: u8 = 1;

    fn get_a(msg: &MyMessage) -> i32 {
        if has_a(msg) { msg.a } else { 0 }
    }

    fn get_b(msg: &MyMessage) -> i32 {
        if has_b(msg) { msg.b } else { 5 }
    }

    fn set_a(msg: &mut MyMessage, val: i32) {
        msg.presence |= (1 << A_BIT);
        msg.a = val;
    }

    fn set_b(msg: &mut MyMessage, val: i32) {
        msg.presence |= (1 << B_BIT);
        msg.b = val;
    }

    fn clear_a(msg: &mut MyMessage) {
        msg.presence &= !(1 << A_BIT);
    }

    fn clear_b(msg: &mut MyMessage) {
        msg.presence &= !(1 << B_BIT);
    }

    fn has_a(msg: &MyMessage) -> bool {
        msg.presence & (1 << A_BIT) != 0
    }

    fn has_b(msg: &MyMessage) -> bool {
        msg.presence & (1 << B_BIT) != 0
    }

    #[derive(Debug)]
    struct ProxyVtable {
        get: fn(&MyMessage) -> i32,
        set: fn(&mut MyMessage, val: i32),
        clear: fn(&mut MyMessage),
        has: fn(&MyMessage) -> bool,
    }

    /// A proxy for a `i32` that is accessed through methods on a vtable.
    struct VtableProxied;

    impl Proxied for VtableProxied {
        type View<'a> = VtableProxiedView;
        type Mut<'a> = VtableProxiedMut<'a>;
    }

    impl OptionalProxied for VtableProxied {
        // In this case, the `PresentMutData` and `AbsentMutData` are identical to the
        // `Mut` in layout. Other types/runtimes could require otherwise, e.g. `Mut`
        // could be defined to only have get/set functions in its vtable, and not
        // has/clear.
        type PresentMutData<'a> = VtableProxiedMut<'a>;
        type AbsentMutData<'a> = VtableProxiedMut<'a>;

        fn clear_present_field<'a>(
            present_mutator: Self::PresentMutData<'a>,
        ) -> Self::AbsentMutData<'a> {
            (present_mutator.vtable.clear)(&mut *present_mutator.msg);
            present_mutator
        }

        fn set_absent_to_default<'a>(
            absent_mutator: Self::AbsentMutData<'a>,
        ) -> Self::PresentMutData<'a> {
            absent_mutator.as_view().val().set_on_absent(Private, absent_mutator)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct VtableProxiedView {
        val: i32,
    }

    impl VtableProxiedView {
        fn val(&self) -> i32 {
            self.val
        }

        fn read(msg: &MyMessage, vtable: &ProxyVtable) -> Self {
            VtableProxiedView { val: (vtable.get)(msg) }
        }
    }

    impl<'a> ViewProxy<'a> for VtableProxiedView {
        type Proxied = VtableProxied;

        fn as_view(&self) -> View<'a, VtableProxied> {
            *self
        }

        fn into_view<'shorter>(self) -> View<'shorter, VtableProxied>
        where
            'a: 'shorter,
        {
            self
        }
    }

    #[derive(Debug)]
    struct VtableProxiedMut<'a> {
        msg: &'a mut MyMessage,
        vtable: &'a ProxyVtable,
    }

    impl<'a> ViewProxy<'a> for VtableProxiedMut<'a> {
        type Proxied = VtableProxied;

        fn as_view(&self) -> View<'_, VtableProxied> {
            VtableProxiedView::read(self.msg, self.vtable)
        }

        fn into_view<'shorter>(self) -> View<'shorter, VtableProxied>
        where
            'a: 'shorter,
        {
            VtableProxiedView::read(self.msg, self.vtable)
        }
    }

    impl<'a> MutProxy<'a> for VtableProxiedMut<'a> {
        fn as_mut(&mut self) -> Mut<'_, VtableProxied> {
            VtableProxiedMut { msg: self.msg, vtable: self.vtable }
        }

        fn into_mut<'shorter>(self) -> Mut<'shorter, VtableProxied>
        where
            'a: 'shorter,
        {
            self
        }
    }

    impl SettableValue<VtableProxied> for View<'_, VtableProxied> {
        fn set_on(self, _private: Private, mutator: Mut<VtableProxied>) {
            self.val().set_on(Private, mutator)
        }

        fn set_on_absent<'a>(
            self,
            _private: Private,
            absent_mutator: <VtableProxied as OptionalProxied>::AbsentMutData<'a>,
        ) -> <VtableProxied as OptionalProxied>::PresentMutData<'a> {
            self.val().set_on_absent(Private, absent_mutator)
        }
    }

    impl SettableValue<VtableProxied> for i32 {
        fn set_on(self, _private: Private, mutator: Mut<VtableProxied>) {
            (mutator.vtable.set)(mutator.msg, self)
        }

        fn set_on_absent<'a>(
            self,
            _private: Private,
            absent_mutator: <VtableProxied as OptionalProxied>::AbsentMutData<'a>,
        ) -> <VtableProxied as OptionalProxied>::PresentMutData<'a> {
            (absent_mutator.vtable.set)(absent_mutator.msg, self);
            absent_mutator
        }
    }

    #[test]
    fn test_field_entry() {
        let mut m1 = MyMessage::default();
        let mut m2 = MyMessage::default();

        let mut m1_a = m1.a_mut();
        assert!(matches!(m1_a, Optional::Unset(_)));
        assert_eq!(m1_a.as_view().val(), 0);

        assert_eq!(m2.b().val(), 5);

        let mut m2_b = m2.b_mut();
        assert!(m2_b.is_unset());
        assert_eq!(m2_b.as_view().val(), 5);

        m2_b.set(10);
        assert!(m2_b.is_set());
        assert!(matches!(m2_b, Optional::Set(_)));
        assert_eq!(m2_b.as_view().val(), 10);

        assert_eq!(m1_a.or_default().get().val(), 0);
        assert_eq!(m1.a_opt(), Optional::Set(VtableProxiedView { val: 0 }));
        m1.a_mut().clear();

        assert_eq!(m1.a().val(), 0);
        assert_eq!(m1.b().val(), 5);
        assert_eq!(m2.a().val(), 0);
        assert_eq!(m2.b().val(), 10);
    }

    #[test]
    fn test_present_field() {
        let mut m = MyMessage::default();
        m.a_mut().set(10);
        match m.a_mut() {
            Optional::Set(mut present) => {
                assert_eq!(present.as_view().val(), 10);
                present.set(20);
                assert_eq!(present.as_view().val(), 20);
                present.into_mut().set(30);
            }
            Optional::Unset(_) => unreachable!(),
        }
        assert_eq!(m.a_opt(), Optional::Set(VtableProxiedView { val: 30 }));
        m.b_mut().set(20);
        match m.b_mut() {
            Optional::Set(present) => present.clear(),
            Optional::Unset(_) => unreachable!(),
        };
        assert_eq!(m.b_opt(), Optional::Unset(VtableProxiedView { val: 5 }));
    }

    #[test]
    fn test_absent_field() {
        let mut m = MyMessage::default();
        match m.a_mut() {
            Optional::Set(_) => unreachable!(),
            Optional::Unset(absent) => {
                assert_eq!(absent.as_view().val(), 0);
                absent.set(20);
            }
        }
        assert_eq!(m.a_opt(), Optional::Set(VtableProxiedView { val: 20 }));
        match m.b_mut() {
            Optional::Set(_) => unreachable!(),
            Optional::Unset(absent) => {
                assert_eq!(absent.as_view().val(), 5);
                absent.set_default();
            }
        }
        assert_eq!(m.b_opt(), Optional::Set(VtableProxiedView { val: 5 }));
    }
}
