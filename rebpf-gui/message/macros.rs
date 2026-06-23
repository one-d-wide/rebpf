#[macro_export]
macro_rules! to_from_hashmap_all {
    (struct $name:ident {
        $($field:ident: $type:ty,)*
    }) => {
        #[derive(Debug, Clone, Default, PartialEq)]
        pub struct $name {
            $(pub $field: $type,)*
        }
        impl $name {
            pub fn from_hashmap(h: HashMap<String, String>) -> Self {
                Self::from_iter(h.into_iter())
            }
            pub fn from_iter(h: impl Iterator<Item = (String, String)>) -> Self {
                let mut s = Self::default();
                for (k, v) in h {
                    match k.replace("-", "_").as_str() {
                        $(stringify!($field) => s.$field = v.parse().unwrap_or_default(),)*
                        _ => {},
                    }
                }
                s
            }
            pub fn into_hashmap(&self) -> HashMap<&'static str, String> {
                let mut h = HashMap::new();
                $(
                    h.insert(stringify!($field), format!("{}", self.$field));
                )*
                h
            }
        }
    };
}

#[macro_export]
macro_rules! to_from_hashmap {
    (
        $(#[$struct_item:meta])*
        struct $name:ident {
            $(
                $(#[$item:meta])*
                    $($field:ident)*
                    $(=> $afield:ident)*
                    $(=> => $dfield:ident)*
                    $(=> => => $sfield:ident)*
                    : $type:ty,
            )*
        }
    ) => {
        $(#[$struct_item])*
        pub struct $name {
            $(
                $(#[$item])*
                pub $($field)*$($afield)*$($dfield)*$($sfield)*: $type,
            )*
        }
        impl $name {
            pub fn from_hashmap(h: HashMap<String, String>, $($($dfield: $type,)*)*) -> Self {
                Self::from_iter(h.into_iter(), $($($dfield,)*)*)
            }
            pub fn from_iter(h: impl Iterator<Item = (String, String)>, $($($dfield: $type,)*)*) -> Self {
                let mut s = Self::default();
                $( $( s.$dfield = $dfield; )* )*
                for (k, v) in h {
                    #[allow(irrefutable_let_patterns)]
                    match k.replace('-', "_").as_str() {
                        $(
                            $(stringify!($field)  => if let Ok(v) = v.parse() { s.$field = v; },)*
                            $(stringify!($afield)  => if let Ok(v) = v.parse() { s.$afield = v; },)*
                            $(stringify!($dfield)  => if let Ok(v) = v.parse() { s.$dfield = v; },)*
                        )*
                        _ => {},
                    }
                }
                s
            }
            pub fn to_hashmap(&self) -> HashMap<&'static str, String> {
                let mut h = HashMap::new();
                $(
                    $(if self.$field != <$type>::default() {
                        h.insert(stringify!($field), format!("{}", self.$field));
                    })*
                    $(
                        h.insert(stringify!($afield), format!("{}", self.$afield));
                    )*
                    $(
                        h.insert(stringify!($dfield), format!("{}", self.$dfield));
                    )*
                )*
                h
            }
        }
    };
}
