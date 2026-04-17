use criterion::{Criterion, criterion_group, criterion_main};
use rocket::http::{ContentType, Status};
use rocket::local::blocking::Client;
use rocket::serde::json::serde_json;
use rocket_identity::AuthorizationHeader;
use rocket_identity::oauth2::Oauth2Response;
use tracing::{Level, Metadata};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::layer::SubscriberExt;

fn criterion_benchmark(c: &mut Criterion) {
    tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_filter(FilterFn::new(|m: &Metadata| *m.level() >= Level::WARN)),
    );
    let rocket = Client::tracked(test_thing::rocket()).unwrap();

    c.bench_function("token generation", |v| {
        v.iter(|| {
            let resp = rocket
                .post("/auth/token")
                .header(ContentType::Form)
                .header(AuthorizationHeader::Basic {
                    username: "client".into(),
                    password: "secret".into(),
                })
                .body("grant_type=password&username=miaw&password=password")
                .dispatch();

            assert_eq!(resp.status(), Status::Ok);
            let text = resp.into_string().unwrap();
            serde_json::from_str::<Oauth2Response>(&text).unwrap()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
