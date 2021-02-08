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

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  serializer.serialize_str(&base64::encode(bytes))
}
