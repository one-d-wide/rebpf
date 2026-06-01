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
                if self.$field != <$type>::default() {
                    h.insert(stringify!($field), format!("{}", self.$field));
                }
                )*
                h
            }
        }
    };
}
