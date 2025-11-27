use crate::application::database::storage::storage_schema::dbtmap_private::DbtMapPrivate;

#[derive(Debug)]
pub struct dbtmap {
    inner: DbtMapPrivate<K, V>,
}
