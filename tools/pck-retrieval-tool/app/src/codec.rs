//use serde::{de, Deserialize, Deserializer, Serializer};
use serde::Serializer;

//pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
//where
//  D: Deserializer<'de>,
//{
//  let s = <&str>::deserialize(deserializer)?;
//
//  base64::decode(s).map_err(de::Error::custom)
//}

pub fn serialize_slice<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hexlify(bytes))
}

pub fn hexlify(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());

    for v in data {
        out.push_str(&format!("{:02x}", v));
    }

    out
}
