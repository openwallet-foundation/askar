import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

// TODO: These work with the uint64. However, this type is not 'usable' on the JS side. We should retrieve them as a Uint8Array or convert it somehow...
// This might work by applying a Montgomery reduce

const G1Affine = CStruct({
  x: CArray(ref.types.uint64, 6),
  y: CArray(ref.types.uint64, 6),
})

export const Bls12381g1 = CStruct({
  optional: ref.types.uint8,
  secret: CArray(ref.types.uint64, 4),
  public: G1Affine,
})