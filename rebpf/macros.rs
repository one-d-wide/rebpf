#[macro_export]
macro_rules! to_from_hashmap {
    (
        $(#[$struct_item:meta])*
        struct $name:ident {
            $(
                $(#[$item:meta])* $($field:ident)*$(=> $afield:ident)*$(=> => $dfield:ident)*: $type:ty,
            )*
        }
    ) => {
        $(#[$struct_item])*
        pub struct $name {
            $(
                $(#[$item])*
                pub $($field)*$($afield)*$($dfield)*: $type,
            )*
        }
        impl $name {
            pub fn from_hashmap(h: HashMap<String, String>, $($($dfield: $type,)*)*) -> eyre::Result<Self> {
                Self::from_iter(h.into_iter(), $($($dfield,)*)*)
            }
            pub fn from_iter(h: impl Iterator<Item = (String, String)>, $($($dfield: $type,)*)*) -> eyre::Result<Self> {
                let mut s = Self::default();
                $( $( s.$dfield = $dfield; )* )*
                for (k, v) in h {
                    match k.as_str() {
                        $(
                            $(stringify!($field) => s.$field = v.parse()?,)*
                            $(stringify!($afield) => s.$afield = v.parse()?,)*
                            $(stringify!($dfield) => s.$dfield = v.parse()?,)*
                        )*
                        _ => bail!("Unknown {} field: {:?}. Expected one of: {}", stringify!($name), k, stringify!($($($field)*$($afield)*$($dfield)*),*)),
                    }
                }
                Ok(s)
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

#[macro_export]
macro_rules! to_from_hashmap_or_default {
    (
        $(#[$struct_item:meta])*
        struct $name:ident {
            $(
                $(#[$item:meta])* $($field:ident)*$(=> $afield:ident)*$(=> => $dfield:ident)*: $type:ty,
            )*
        }
    ) => {
        $(#[$struct_item])*
        pub struct $name {
            $(
                $(#[$item])*
                pub $($field)*$($afield)*$($dfield)*: $type,
            )*
        }
        impl $name {
            pub fn from_hashmap(h: HashMap<String, String>,  def: &Self, $($($dfield: $type,)*)*) -> eyre::Result<Self> {
                Self::from_iter(h.into_iter(), def, $($($dfield,)*)*)
            }
            pub fn from_iter(h: impl Iterator<Item = (String, String)>, def: &Self, $($($dfield: $type,)*)*) -> eyre::Result<Self> {
                let mut s = def.clone();
                $( $( s.$dfield = $dfield; )* )*
                for (k, v) in h {
                    match k.as_str() {
                        $(
                            $(stringify!($field) => s.$field = v.parse()?,)*
                            $(stringify!($afield) => s.$afield = v.parse()?,)*
                            $(stringify!($dfield) => s.$dfield = v.parse()?,)*
                        )*
                        _ => bail!("Unknown {} field: {:?}. Expected one of: {}", stringify!($name), k, stringify!($($($field)*$($afield)*$($dfield)*),*)),
                    }
                }
                Ok(s)
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

#[macro_export]
macro_rules! to_from_enum {
    ($(#[$enum_item:meta])* enum $enum:ident {
        $(
            $(#[[rename = $rename:literal]])*
            $(#[[alias = $alias:literal]])*
            $(#[$item:meta])*
            $variant:ident,
        )*
    }) => {
        $(#[$enum_item])*
        pub enum $enum {
            $(
                $(#[$item])*
                $variant,
            )*
        }

        impl FromStr for $enum {
            type Err = eyre::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(
                    $($rename => Ok(Self::$variant),)*
                    $($alias => Ok(Self::$variant),)*
                    stringify!($variant) => Ok(Self::$variant),
                    )*
                    _ => bail!("Unknown {}: {:?}. Expected one of: {}", stringify!($enum), s, stringify!($($variant),*)),
                }
            }
        }

        impl Display for $enum {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                #[allow(unreachable_patterns)]
                let s = match self {
                    $(
                    $(Self::$variant => $rename,)*
                    Self::$variant => stringify!($variant),
                    )*
                };
                f.write_str(s)
            }
        }
    };
}
