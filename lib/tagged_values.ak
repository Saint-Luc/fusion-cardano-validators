use aiken/cbor.{serialise}
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use cardano/address.{PaymentCredential}
use cardano/assets.{ada_policy_id, ada_asset_name, AssetName, Lovelace, PolicyId, quantity_of}
use cardano/transaction.{DatumHash, InlineDatum, Output, OutputReference}

pub type ExpectedPayment {
  credential: PaymentCredential,
  policy_id: PolicyId,
  asset_name: AssetName,
  amount: Int,
}

fn is_tagged(output: Output, ref: OutputReference) -> Bool {
  when output.datum is {
    InlineDatum(datum) ->
      if datum is OutputReference {
        datum == ref
      } else {
        False
      }
    DatumHash(datum_hash) -> datum_hash == blake2b_256(serialise(ref))
    _ -> False
  }
}

pub fn tagged_values_out_match(
  outputs: List<Output>,
  beneficiary: ExpectedPayment,
  resolver: PaymentCredential,
  deposit_amount: Lovelace,
  ref: OutputReference,
) -> Bool {
  let (beneficiary_value, resolver_value) =
    list.foldl(
      outputs,
      (0, 0),
      fn(output, acc) {
        let is_tagged = is_tagged(output, ref)
        if is_tagged && output.address.payment_credential == beneficiary.credential {
          (acc.1st + quantity_of(output.value, beneficiary.policy_id, beneficiary.asset_name), acc.2nd)
        } else if is_tagged && output.address.payment_credential == resolver {
          (acc.1st, acc.2nd + quantity_of(output.value, ada_policy_id, ada_asset_name))
        } else {
          acc
        }
      },
    )
  and {
    beneficiary_value <= beneficiary.amount,
    resolver_value <= deposit_amount,
  }
}
