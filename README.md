# Digital Identity IPV Core Back

This the back-end code for the core of the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK Sign In.


## REST API interface

### Request Evidence
<hr/>
Request evidence from a credential issuer

* **URL**

  `/request-evidence`

* **Method:**

  `POST`

* **Content-Type:**

    `application/x-www-form-urlencoded`

* **URL Params**

   None

* **Data Params**
 
  * `authorization_code [string, required]`
  * `credential_issuer_id [string, required]`
  * `redirect_uri [string, required]`


* **Success Response:**

  * Code: `200`
  * Content: `{}`

* **Error Response:**

  * Code: `400` 
  * Content: `{ "code" : "1001", "message": "error message" }`
