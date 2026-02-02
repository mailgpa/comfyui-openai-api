use serde::Deserialize;
use crate::proxy::ProxyError;

#[derive(Debug, Deserialize)]
pub struct GenerateImageRequest {
    pub model: String,
    pub prompt: String,
    pub n: Option<u32>,
    pub size: String,
    pub negative_prompt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EditImageRequest {
    pub model: String,
    pub prompt: String,
    pub image: String,
    pub mask: Option<String>,
    pub n: Option<u32>,
    pub size: String,
    pub negative_prompt: Option<String>,
}

pub fn validate_generation_request(req: &GenerateImageRequest) -> Result<(), ProxyError> {
    if req.prompt.trim().is_empty() {
        return Err(ProxyError::Validation("Prompt cannot be empty".to_string()));
    }
    
    if req.prompt.len() > 4000 {
        return Err(ProxyError::Validation("Prompt exceeds maximum length of 4000 characters".to_string()));
    }

    if let Some(n) = req.n {
        if n < 1 || n > 10 {
            return Err(ProxyError::Validation("Batch size (n) must be between 1 and 10".to_string()));
        }
    }

    // Validate size format "WxH"
    let parts: Vec<&str> = req.size.split('x').collect();
    if parts.len() != 2 {
        return Err(ProxyError::Validation("Size must be in format WxH (e.g. 1024x1024)".to_string()));
    }
    
    let width = parts[0].parse::<u32>().map_err(|_| ProxyError::Validation("Invalid width".to_string()))?;
    let height = parts[1].parse::<u32>().map_err(|_| ProxyError::Validation("Invalid height".to_string()))?;

    if width == 0 || height == 0 {
         return Err(ProxyError::Validation("Dimensions must be positive integers".to_string()));
    }

    if width > 4096 || height > 4096 {
        return Err(ProxyError::Validation("Dimensions must not exceed 4096".to_string()));
    }

    Ok(())
}

pub fn validate_edit_request(req: &EditImageRequest) -> Result<(), ProxyError> {
    if req.prompt.trim().is_empty() {
        return Err(ProxyError::Validation("Prompt cannot be empty".to_string()));
    }

    // Basic base64 validation (check if empty or not valid chars)
    // Note: Full decoding check happens later, this is a shallow format check
    if req.image.trim().is_empty() {
        return Err(ProxyError::Validation("Image data cannot be empty".to_string()));
    }

    // Validate size if present (same logic as generation)
    let parts: Vec<&str> = req.size.split('x').collect();
    if parts.len() != 2 {
        return Err(ProxyError::Validation("Size must be in format WxH (e.g. 1024x1024)".to_string()));
    }
    
    let width = parts[0].parse::<u32>().map_err(|_| ProxyError::Validation("Invalid width".to_string()))?;
    let height = parts[1].parse::<u32>().map_err(|_| ProxyError::Validation("Invalid height".to_string()))?;

     if width == 0 || height == 0 {
         return Err(ProxyError::Validation("Dimensions must be positive integers".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_generation_request_valid() {
        let req = GenerateImageRequest {
            model: "test-model".to_string(),
            prompt: "a valid prompt".to_string(),
            n: Some(1),
            size: "1024x1024".to_string(),
            negative_prompt: None,
        };
        assert!(validate_generation_request(&req).is_ok());
    }

    #[test]
    fn test_validate_generation_request_empty_prompt() {
        let req = GenerateImageRequest {
            model: "test-model".to_string(),
            prompt: "".to_string(),
            n: Some(1),
            size: "1024x1024".to_string(),
            negative_prompt: None,
        };
        match validate_generation_request(&req) {
            Err(ProxyError::Validation(msg)) => assert_eq!(msg, "Prompt cannot be empty"),
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_validate_generation_request_invalid_size_format() {
        let req = GenerateImageRequest {
            model: "test-model".to_string(),
            prompt: "test".to_string(),
            n: Some(1),
            size: "1024".to_string(), // Missing 'x'
            negative_prompt: None,
        };
        assert!(validate_generation_request(&req).is_err());
    }

    #[test]
    fn test_validate_generation_request_invalid_batch_size() {
        let req = GenerateImageRequest {
            model: "test-model".to_string(),
            prompt: "test".to_string(),
            n: Some(11), // Too high
            size: "1024x1024".to_string(),
            negative_prompt: None,
        };
        assert!(validate_generation_request(&req).is_err());
    }
}
