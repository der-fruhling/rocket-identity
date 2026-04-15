use tracing::{Level, Metadata};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[rocket::launch]
fn launch() -> _ {
    tracing_subscriber::registry()
        .with(filter_fn(|m: &Metadata| *m.level() <= Level::INFO || m.target().contains("rocket_identity") || m.target().contains("test_thing")))
        .with(tracing_subscriber::fmt::layer())
        .init();
    test_thing::rocket()
}