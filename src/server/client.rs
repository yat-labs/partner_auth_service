use actix_web::client::{Client, Connector};
use std::time::Duration;

pub fn client_with_connector_timeout(connector_timeout: Option<Duration>) -> Client {
    let duration = connector_timeout.unwrap_or(Duration::from_secs(30));
    let connector = Connector::new().timeout(duration).finish();
    let client = Client::builder().connector(connector).finish();
    client
}
