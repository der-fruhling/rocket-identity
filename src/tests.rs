use crate::{all, allow, any, compose, const_str, deny, Scope};

const_str! {
    type AllowTest = "test";
    type AllowCool = "cool";
    type AllowOpenID = "openid";
}

#[test]
fn always_true() {
    assert_eq!(<allow![true]>::test(&["test"]), true);
}

#[test]
fn always_false() {
    assert_eq!(<allow![false]>::test(&["test"]), false);
}

#[test]
fn scope_test() {
    assert_eq!(<allow![AllowTest]>::test(&["test"]), true);
    assert_eq!(<allow![AllowTest]>::test(&["cool"]), false);
}

#[test]
fn scope_any_of() {
    assert_eq!(<allow![any!(AllowTest, AllowCool)]>::test(&["test"]), true);
    assert_eq!(<allow![any!(AllowTest, AllowCool)]>::test(&["cool"]), true);
    assert_eq!(
        <allow![any!(AllowTest, AllowCool)]>::test(&["test", "cool"]),
        true
    );
    assert_eq!(
        <allow![any!(AllowTest, AllowCool)]>::test(&["openid"]),
        false
    );
}

#[test]
fn scope_all_of() {
    assert_eq!(<allow![all!(AllowTest, AllowCool)]>::test(&["test"]), false);
    assert_eq!(<allow![all!(AllowTest, AllowCool)]>::test(&["cool"]), false);
    assert_eq!(
        <allow![all!(AllowTest, AllowCool)]>::test(&["test", "cool"]),
        true
    );
}

#[test]
fn scope_not() {
    assert_eq!(<allow![!AllowTest]>::test(&["test"]), false);
    assert_eq!(<allow![!AllowCool]>::test(&["test"]), true);

    assert_eq!(<deny![AllowTest]>::test(&["test"]), false);
    assert_eq!(<deny![AllowCool]>::test(&["test"]), true);
}

#[test]
fn scope_compose() {
    assert_eq!(<compose! { _ => allow![true] }>::test(&["test"]), true);
    assert_eq!(<compose! { _ => allow![false] }>::test(&["test"]), false);

    assert_eq!(
        <compose! { AllowTest => AllowCool }>::test(&["test"]),
        false
    );
    assert_eq!(
        <compose! { AllowTest => AllowCool }>::test(&["cool"]),
        false
    );
    assert_eq!(
        <compose! { AllowTest => AllowCool }>::test(&["test", "cool"]),
        true
    );

    type Composed = compose! {
        AllowTest => allow![],
        AllowCool => deny![],
        @ => AllowOpenID
    };

    assert_eq!(Composed::test(&["test"]), true);
    assert_eq!(Composed::test(&["test", "cool"]), true);
    assert_eq!(Composed::test(&["cool"]), false);
    assert_eq!(Composed::test(&["openid"]), true);
    assert_eq!(Composed::test(&["openid", "cool"]), false);
    assert_eq!(Composed::test(&["openid", "cool", "test"]), true);
}
