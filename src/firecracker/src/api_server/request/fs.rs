// SPDX-License-Identifier: Apache-2.0
use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::fs::FsConfig;

pub(crate) fn parse_put_fs(body: &Body, id: Option<&str>) -> Result<ParsedRequest, RequestError> {
    let id = checked_id(id.ok_or(RequestError::EmptyID)?)?;
    let config: FsConfig = serde_json::from_slice(body.raw())?;
    if id != config.fs_id {
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Path id must match fs_id".into(),
        ));
    }
    config
        .validate()
        .map_err(|e| RequestError::Generic(StatusCode::BadRequest, e.to_string()))?;
    Ok(ParsedRequest::new_sync(VmmAction::InsertFs(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_put_fs_validates_id_tag_and_unknown_fields() {
        let body = Body::new(r#"{"fs_id":"project","tag":"workspace","socket":"/fs.sock"}"#);
        parse_put_fs(&body, Some("project")).unwrap();
        parse_put_fs(&body, Some("other")).unwrap_err();
        parse_put_fs(&body, None).unwrap_err();
        parse_put_fs(
            &Body::new(r#"{"fs_id":"p","tag":"../escape","socket":"/s"}"#),
            Some("p"),
        )
        .unwrap_err();
        parse_put_fs(
            &Body::new(r#"{"fs_id":"p","tag":"p","socket":"/s","read_only":true}"#),
            Some("p"),
        )
        .unwrap_err();
    }
}
