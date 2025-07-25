// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Resource record related components, e.g. `Name` aka label, `Record`, `RData`, ...

pub mod dns_class;
// TODO: rename to sec
pub mod domain;
mod lower_name;
pub mod rdata;
pub mod record_data;
pub mod record_type;
pub(crate) mod record_type_set;
pub mod resource;
mod rr_key;
mod rr_set;
pub mod serial_number;

use core::fmt::{Debug, Display};

use crate::{
    error::ProtoResult,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, Restrict},
};

pub use self::dns_class::DNSClass;
pub use self::domain::{IntoName, Name};
pub use self::record_data::RData;
pub use self::record_type::RecordType;
pub(crate) use self::record_type_set::RecordTypeSet;
pub use self::resource::Record;
pub use self::rr_set::RecordSet;
pub use self::rr_set::RrsetRecords;
pub use lower_name::LowerName;
pub use rr_key::RrKey;
pub use serial_number::SerialNumber;

/// RecordData that is stored in a DNS Record.
///
/// This trait allows for generic usage of `RecordData` types inside the `Record` type. Specific RecordData types can be used to enforce compile time constraints on a Record.
pub trait RecordData: Clone + Sized + PartialEq + Eq + Display + Debug + BinEncodable {
    /// Attempts to borrow this RecordData from the RData type, if it is not the correct type the original is returned
    fn try_borrow(data: &RData) -> Option<&Self>;

    /// Get the associated RecordType for the RecordData
    fn record_type(&self) -> RecordType;

    /// Converts this RecordData into generic RecordData
    fn into_rdata(self) -> RData;

    /// RDLENGTH = 0
    fn is_update(&self) -> bool {
        false
    }
}

pub(crate) trait RecordDataDecodable<'r>: Sized {
    /// Read the RecordData from the data stream.
    ///
    /// * `decoder` - data stream from which the RData will be read
    /// * `record_type` - specifies the RecordType that has already been read from the stream
    /// * `length` - the data length that should be read from the stream for this RecordData
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self>;
}

impl<'r, T> RecordDataDecodable<'r> for T
where
    T: 'r + BinDecodable<'r> + Sized,
{
    fn read_data(decoder: &mut BinDecoder<'r>, _length: Restrict<u16>) -> ProtoResult<Self> {
        T::read(decoder)
    }
}
