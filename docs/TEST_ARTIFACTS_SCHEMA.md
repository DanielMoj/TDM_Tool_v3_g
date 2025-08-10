# TEST_ARTIFACTS_SCHEMA

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "TDMx Test Summary",
  "type": "object",
  "required": [
    "summary",
    "failures",
    "warnings",
    "coverage"
  ],
  "properties": {
    "summary": {
      "type": "object",
      "required": [
        "passed",
        "failed",
        "skipped",
        "duration_sec"
      ],
      "properties": {
        "passed": {
          "type": "integer",
          "minimum": 0
        },
        "failed": {
          "type": "integer",
          "minimum": 0
        },
        "skipped": {
          "type": "integer",
          "minimum": 0
        },
        "duration_sec": {
          "type": "number",
          "minimum": 0
        }
      }
    },
    "failures": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "test",
          "message"
        ],
        "properties": {
          "test": {
            "type": "string"
          },
          "message": {
            "type": "string"
          },
          "log_excerpt": {
            "type": "string"
          },
          "suggested_fix": {
            "type": "string"
          },
          "area": {
            "type": "string"
          }
        }
      }
    },
    "warnings": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "coverage": {
      "type": "object",
      "required": [
        "overall"
      ],
      "properties": {
        "overall": {
          "type": "string"
        },
        "low_files": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      }
    }
  }
}
```
