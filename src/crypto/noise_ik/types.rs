/// Owned opaque payload exchanged by the Noise-IK provider and V2 adapter.
pub(crate) struct NoiseIkPayload(pub(crate) Box<[u8]>);
