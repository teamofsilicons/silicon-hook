//! Configurable verification of provider webhook signatures.
//!
//! Every provider signs differently, so a hook owner describes the signing
//! scheme with a small expression language instead of choosing from a fixed
//! list of vendors. An expression combines blocks of the captured request
//! (`request.raw_body`, `request.headers["webhook-id"]`, `request.query.t`,
//! ...) with pure functions (`concat`, `sha256`, `hex`, `base64`, ...) to
//! produce the exact bytes the provider signed, and a second expression
//! locates the presented signature. The configured algorithm and encodings
//! complete the description.
//!
//! The default configuration implements the Standard Webhooks convention:
//! HMAC-SHA-256 over `webhook-id.webhook-timestamp.body`, presented in base64
//! in the `webhook-signature` header.

mod ast;
mod config;
mod eval;
mod keys;
mod lexer;
mod parser;
mod value;
mod verify;

pub use ast::{Call, Expr, Function, Path, Root, Segment, SortOrder};
pub use config::{
    ConfigError, DEFAULT_PAYLOAD_EXPRESSION, DEFAULT_SIGNATURE_EXPRESSION, Expression,
    MAX_SECRET_BYTES, SecretDecodeError, SecretEncoding, SignatureAlgorithm, SignatureConfig,
    SignatureEncoding,
};
pub use eval::{EvalContext, EvalError, evaluate};
pub use keys::{MAX_PUBLIC_KEY_BYTES, MIN_RSA_MODULUS_BITS, PublicKey, PublicKeyError};
pub use lexer::{MAX_EXPRESSION_BYTES, ParseError, ParseErrorKind};
pub use parser::parse;
pub use value::{Value, ValueError};
pub use verify::{
    HookContext, MAX_PRESENTED_SIGNATURE_BYTES, MAX_SIGNATURE_CANDIDATES, MaterialError,
    RejectionReason, VerificationMaterial, VerificationOutcome, verify,
};
