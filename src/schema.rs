// @generated automatically by Diesel CLI.

diesel::table! {
    threats (id) {
        id -> Int4,
        message -> Text,
        threat_type -> Text,
        timestamp -> Nullable<Timestamp>,
    }
}
