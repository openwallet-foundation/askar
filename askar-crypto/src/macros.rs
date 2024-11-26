macro_rules! maybeuninit_part {
    ($val:expr, $member:tt) => {{
        fn _to_mbi<T>(addr: *mut T) -> *mut ::core::mem::MaybeUninit<T> {
            addr.cast()
        }
        unsafe { &mut *_to_mbi(::core::ptr::addr_of_mut!((*$val.as_mut_ptr()).$member)) }
    }};
}
