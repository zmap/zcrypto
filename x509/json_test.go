package x509

import (
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateJSON(t *testing.T) {
	tests := []struct {
		file     string
		expected string
	}{
		{
			file:     "dadrian.io.pem",
			expected: `{"version":3,"serial_number":"305886419700358386478020960166137792057035","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["Let's Encrypt Authority X3"],"country":["US"],"organization":["Let's Encrypt"]},"issuer_dn":"CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US","validity":{"start":"2017-04-13T19:32:00Z","end":"2017-07-12T19:32:00Z","length":7776000},"subject":{"common_name":["dadrian.io"]},"subject_dn":"CN=dadrian.io","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"8qJlL2z5O7SyETMVLpWZsi/ROt/QAw5YoykU/LCUT1O+aeQssbjSPLMxkG7d1GD4wIRP9ssXNIeRzARKBFtjznn+pBmcMCgRL9vN28zZDnLhdbK0mAZZiO+cmt/b8iju+iacZdZCAO0B4BrmP/GoS7U/BrTD52ATR/uLqCjsEQz6Udu82OxHGZbhUzyzaX9qKfHb5MGY8MDwvXjUEo/3B9BY86iz6hZqRMwYJJn1cy2rb3FR1djUNEB6W/nUy9bX/FJhKSgd3lxAg2nYTAh4u2WYQ1zwJBrBVG5qsXwYfD/p7GxBenh5uSj2nefuNStu59u2VgSI15nVkclMaWcyZQ==","length":2048},"fingerprint_sha256":"76399969b581934c3a94e49aacda4e8b75f47f0ee78f4243f1cde7be71570f38"},"extensions":{"key_usage":{"digital_signature":true,"key_encipherment":true,"value":5},"basic_constraints":{"is_ca":false},"subject_alt_name":{"dns_names":["dadrian.io"]},"authority_key_id":"a84a6a63047dddbae6d139b7a64565eff3a8eca1","subject_key_id":"8437e8fbed4c19b3d49142e1f43f698297d72780","extended_key_usage":{"server_auth":true,"client_auth":true},"certificate_policies":[{"id":"2.23.140.1.2.1"},{"id":"1.3.6.1.4.1.44947.1.1.1","cps":["http://cps.letsencrypt.org"],"user_notice":[{"explicit_text":"This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/"}]}],"authority_info_access":{"ocsp_urls":["http://ocsp.int-x3.letsencrypt.org/"],"issuer_urls":["http://cert.int-x3.letsencrypt.org/"]}},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"Mdm7dQzo4ptGTGwfXiMaUJbQOVsvWu/EBYDZfEruO1a9PHffp1/u/8KuEyn5/8HEN1mRJ0/4W3v98DK0kwEG8jZhG9EKvD1rwMwNEEpZxs/T3yJE16lCwHHqCo59wDaUHiLI2clSe5K6CuB6d7P+s0KoaYQ/zF7F3+1v1ULWoxy2ugZWLZW2NE6QHmmEOAt0b7RHaCedgXYbEgMReLnOEbKEW0XK0SWLB0ZirhuaJizWP2hWXrkMflRNRNHN1qjWGwz6N3xwTgCo77l4TJqIUHKmagLafAUzxFWmFG3Yiqpskl5xhCSiEEC4VgIfffxA+CwiB84Hf2LUUeYnWQcmAw==","valid":false,"self_signed":false},"fingerprint_md5":"2717af7f6459742355b9cdd60c6cd46d","fingerprint_sha1":"88f3bd5c2d8ca749aeb04823c19d9fea9d8b398d","fingerprint_sha256":"9f5c853220c6e2015390a38cd0cba8b3a5caac6344b9c9223ec3d2612a846d3d","tbs_noct_fingerprint":"3e95ebcea16c31f495123aed393deca706f0f796cd6187a5044c1a2161fe2e21","spki_subject_fingerprint":"8a5d4cbab48316c11c5b2fa053ad119f807bf41a29cc97f713edd3e46c3f53a2","tbs_fingerprint":"3e95ebcea16c31f495123aed393deca706f0f796cd6187a5044c1a2161fe2e21","validation_level":"DV","names":["dadrian.io"],"redacted":false}`,
		},
		{
			file:     "ian.test.cert",
			expected: `{"version":3,"serial_number":"13905679301969112323","signature_algorithm":{"name":"SHA1-RSA","oid":"1.2.840.113549.1.1.5"},"issuer":{"common_name":["IAN Test"],"country":["US"],"locality":["Champaign"],"province":["IL"],"organization":["UIUC"],"organizational_unit":["CS"],"email_address":["test@iantest.com"]},"issuer_dn":"emailAddress=test@iantest.com, CN=IAN Test, OU=CS, O=UIUC, L=Champaign, ST=IL, C=US, emailAddress=test@iantest.com","validity":{"start":"2016-09-07T21:10:12Z","end":"2017-09-07T21:10:12Z","length":31536000},"subject":{"common_name":["IAN Test"],"country":["US"],"locality":["Champaign"],"province":["IL"],"organization":["UIUC"],"organizational_unit":["CS"],"email_address":["test@iantest.com"]},"subject_dn":"emailAddress=test@iantest.com, CN=IAN Test, OU=CS, O=UIUC, L=Champaign, ST=IL, C=US, emailAddress=test@iantest.com","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"5Sj63YALzwmLnXNWuFmAZlv6sWelKFbP+SWPPEtsjXGHE8R0rAE6lRjjCPw8CRMIIQgGeyxDuB0kLDiR6gG6aHOOb1hdOcxhS7Cw7YsICeZ7V6fN9+opFGwdKJ998TvWsl1Vw2crfTL0P9YmRivevk9kOVfmj/dFvqRzLL81CmNnDwfsgqo4l1/WxpOpB5+gua5Fu+q3WyEk8oPcr5jX5z4d8AVhi1ZUYBr8wNrlR/RWfTJYqL0uch6hg2dLlzodG7v6kKSH/GVhPd1+eL4Kp4kNaFiJkHstRDz9YZ0y505Z8VF9V3WRsZ7l6JyyRR7dbqJTwiVYM7uESKN2inDMYw==","length":2048},"fingerprint_sha256":"688d5164e9da2ebcbcc8dca96513f500687acc7a70aa025c7f268a75ebc23f71"},"extensions":{"key_usage":{"digital_signature":true,"key_encipherment":true,"value":5},"issuer_alt_name":{"dns_names":["example.1.com","example.2.com"],"email_addresses":["test@iantest.com","test2@iantest2.com"],"ip_addresses":["1.2.3.4"],"other_names":[{"id":"1.2.3.4","value":"DCBEQlZ6YjIxbElHOTBhR1Z5SUdsa1pXNTBhV1pwWlhJPQ=="}],"registered_ids":["1.2.3.4"],"uniform_resource_identifiers":["http://www.insecure.com"]}},"signature":{"signature_algorithm":{"name":"SHA1-RSA","oid":"1.2.840.113549.1.1.5"},"value":"NKUyMbXEPqjfHmhThDqPF5onrwqVAtumI0FQtfZs7V1Ve4fPU+Hc7jNvyGzv3h2qynKORbX+ZgXX1yUaVL3VJBpKogwr8ogpVbr5q/D5KrIwI8nUHF9meMPjDj0imtuE4KqSSvHa9YqT16e1iMwcs9vYEmpetIVs8pGIUp9DtpSKV9sn0ZlaLRO4lA1Cx25N8W5Ue3Qoj78Vl/lZCIBn4Whqpo/h5joOlETNyghzm8Cw0PAMviC/k/rFstizrWa1c8s60Ex5S3A4cdIvF03U5mwYSGMxgfi7TvD6uRlp/L7t6VSxHChq3C9j965Xec2qK6klS/4XXVAizN7/V/6TEA==","valid":true,"self_signed":true},"fingerprint_md5":"b930cccf8bf02db782dadb8e7171d783","fingerprint_sha1":"51e9e3ddf2d7d46bd269851efbcb574aa4ac47c1","fingerprint_sha256":"2b96e909ccec2ef95d0ef20678a05844c46308d44a78958b4fa9e474a522683b","tbs_noct_fingerprint":"7729889cecc4fd392a4b1bff3222093345e3cc0a7b8f35b1fb3b2a7201818093","spki_subject_fingerprint":"d417ddc01fb3d88a50ed9dca6fd7e1484e6043dc64fc743fbb17f57af10cc13b","tbs_fingerprint":"7729889cecc4fd392a4b1bff3222093345e3cc0a7b8f35b1fb3b2a7201818093","validation_level":"unknown","redacted":false}`,
		},
		{
			file:     "name.constraint.test.cert",
			expected: `{"version":3,"serial_number":"18008675309","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["Name constraint"],"country":["US"],"organization":["Mother Nature"],"organizational_unit":["Everything"]},"issuer_dn":", CN=Name constraint, OU=Everything, O=Mother Nature, C=US","validity":{"start":"2055-12-01T06:07:08Z","end":"2056-09-01T21:58:32Z","length":23817084},"subject":{"common_name":["gov.us"],"country":["US"],"locality":["Tallahassee"],"province":["FL"],"street_address":["3210 Holly Mill Run"],"organization":["Extreme Discord"],"organizational_unit":["Chaos"],"postal_code":["30062"]},"subject_dn":", CN=gov.us, postalCode=30062, street=3210 Holly Mill Run, ST=FL, L=Tallahassee, OU=Chaos, O=Extreme Discord, C=US","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"n+JmzHjuCRUfD7xtSNdfRcWjSmr1g13nDYYn/2dfMBz4AxYdlQEiB0/7dcEU7oC1LX+j0RvZW8RzASv/0drgN2WWarUrUmqR1Ka8NzYLyfz0cSoZHnymzSUsTAIqIlrNgbTkOHfYo6wVmIZn1Nrj69ucF/I6oHYmeS/6QrSuPHKMw7rdMkBMs8ydMFAZmBORBxrA1btpxr7OyjYoxaICISzKV3vcC1kC4RRyDp7aqbDM3XaIdioUhLc4R3begfg1N1ouwHMCGyis4RKZSku9sFf537juNeFarBK3YJ7ElSxEpK5+kg7rDNjuUDfzSnk77Ege0K6+a0GHyyT5Ual1Bw==","length":2048},"fingerprint_sha256":"90fd46b51b555e29b770cd37100c738cbf6edb23b894a20e6090476406c21b6b"},"extensions":{"key_usage":{"digital_signature":true,"key_encipherment":true,"certificate_sign":true,"value":37},"basic_constraints":{"is_ca":true},"subject_alt_name":{"dns_names":["gov.us"]},"name_constraints":{"critical":false,"permitted_email_addresses":["email","LulMail"],"permitted_directory_names":[{"common_name":["uiuc.net"],"country":["US"],"locality":["Champaign"],"province":["IL"],"street_address":["601 Wright St"],"organization":["UIUC"],"organizational_unit":["ECE"],"postal_code":["61820"]}],"permitted_registred_id":["1.2.3.4"],"excluded_names":["banned.com"],"excluded_ip_addresses":[{"cidr":"192.168.1.1/16","begin":"192.168.0.0","end":"192.168.255.255","mask":"255.255.0.0"}]},"authority_key_id":"010203","extended_key_usage":{"server_auth":true,"client_auth":true},"certificate_policies":[{"id":"2.23.140.1.2.2"},{"id":"1.2.3.4.5"}],"authority_info_access":{"ocsp_urls":["http://theca.net/ocsp"],"issuer_urls":["http://theca.net/totallythecert.crt"]}},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"SxvJhcCgxbENfrLmAjWN6K7UFstegR1Q1w+kMBhXmP+mXhGQS/YQRdXuXoFSHgoVpoAj+WpMM4PT3oJBBr15M+bkddJQE8tBpBh1w4RJMRTPZg3jNvbtj0Hii0icLfcxVFl9C9tIFMd+AR/24fjbXHcmwr+S4CDn1x0FiruMxgHm0XJ7bKTdAkuGQmZNlifg8tW5MiKt4jFw2qL0l4w28oG85jGObeFap95BsrVwjpV9xAlPGTo2W40AX8n7gsDDlIQ6U199vIrV3AHIYp4us7jbDQxgKEh9rR2lmDhRgyTnMyNNwdN4IYIu4EO+M3HMgSXE/Uq7luYRawlstr0hRQ==","valid":false,"self_signed":false},"fingerprint_md5":"6eaaae82f776e452f1153fa8bb8eef71","fingerprint_sha1":"125ec8dbac641e8052c8124a2a5ecd395b786a17","fingerprint_sha256":"07dfb51c8ba3d84feddee9e627d28c1c93e9cc6df3fdd58211b1c66cf2977e7c","tbs_noct_fingerprint":"4198c18ce4a65233d3fe5d2e115a74ac96f4fe59b12cb7d31c64a3a8fb6792dd","spki_subject_fingerprint":"55d3553d159e050be0cf8a55c9229d8cdd48ad783aa578ad0eb5cebe1bc71131","tbs_fingerprint":"4198c18ce4a65233d3fe5d2e115a74ac96f4fe59b12cb7d31c64a3a8fb6792dd","validation_level":"OV","names":["gov.us"],"redacted":false}`,
		},
		{
			file:     "san.test.cert",
			expected: `{"version":3,"serial_number":"11969031822203118914","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["SAN Test"],"country":["US"],"locality":["Champaign"],"province":["IL"],"organization":["UIUC"],"organizational_unit":["CS"],"email_address":["test@santest.com"]},"issuer_dn":"emailAddress=test@santest.com, CN=SAN Test, OU=CS, O=UIUC, L=Champaign, ST=IL, C=US, emailAddress=test@santest.com","validity":{"start":"2016-08-24T18:55:08Z","end":"2018-08-24T18:55:08Z","length":63072000},"subject":{"common_name":["SAN Test"],"country":["US"],"locality":["Champaign"],"province":["IL"],"organization":["UIUC"],"organizational_unit":["CS"],"email_address":["test@santest.com"]},"subject_dn":"emailAddress=test@santest.com, CN=SAN Test, OU=CS, O=UIUC, L=Champaign, ST=IL, C=US, emailAddress=test@santest.com","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"zNNJPiLkZhaNcLFfuffykzP4925ggaM+XcLoNkvvHivT4bqFKChmhTbE5J9ZGJgy2adniWEApjQHLRhRui6aO4CWkbP63iJTKJ1CyjV2tUO4ObgMsWlsOPD0ccqUdqw3QpqTgvelBIjENl+bB9yXSe+kDb64cQpi9SaT1STVr/CTrDpDD0THdf1GFqFlKM0ioY8u2pa293rn50o9TLtIr4l6kzQaRopzfZPnJ+CWXTjGIp4YypULsbvp8LIcPIRyp/6U7j8XMhJr33DW5wOfPcKBT/aJm5PILRwKHodQ14yNxKW0g+OizTHKdRkVHEKSwFEp4rEfsr20erx6Vyh7Fq+7IjoP/5gTbNJmWRxJ1h88xpCxETNfpqXt4x5LkTA9sXpMNTk4Bpy02k/0KNMqTO2osI5Mof5+hxGe7CkhaB1OujmaoPMRB7+cKCIf5dv1u+0GH4k7YlOwYiev+mHzIOd04rdJG0MN/y60tEgjs7JiC75AKMldRfqHZ+ZII0NV","length":3072},"fingerprint_sha256":"8aef7c362bb4dfc4a83f33dcdcb016b1473ed2a87cb815ddf332f6eb076bd133"},"extensions":{"basic_constraints":{"is_ca":true},"subject_alt_name":{"directory_names":[{"common_name":["My Name"],"country":["US"],"organization":["My Organization"],"organizational_unit":["My Unit"]}],"dns_names":["dns1.test.com","dns2.test.com"],"email_addresses":["email@testsan.com"],"ip_addresses":["1.2.3.4"],"other_names":[{"id":"1.2.3.4","value":"DBVzb21lIG90aGVyIGlkZW50aWZpZXI="}],"registered_ids":["1.2.3.4"],"uniform_resource_identifiers":["http://watchit.com/"]},"authority_key_id":"b970e26ca9347b9f94a434d931d0891cdc273f56","subject_key_id":"b970e26ca9347b9f94a434d931d0891cdc273f56"},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"FAHBXJgYGi3MSKfj8npv+C1LlBbUdSMvqBEm4VSYIrsWHQeAabn4xiEzEs9QX3JsJD/muSo5y7VOiDOOuICPgh8ZDVJ1Rp1IFpr3HZsvLxLaKC7p/6Qc9MOFrZR2zwLjTc4VgVJ2r1X596duXuE/we5RMfAPTrqT20CVuiblsF2vvOJLmQr9o17a0kqAVukkffUoGvHRe1FC4lO4BkJq1DiXzRSUwxXh9Mzb4aGkNzltgP3HSXPzXTAGq9YxDoV86S1ITzTHDlFQpZoCsXXG4FKhw64gKWO3mFAbM8YMp4cLzdci9TRbiJVO/ZZnNROlBfPQTLtxSri5Emj9sWCDLAW3TGfDRDCPsYZGcImhpNFtlUkt+RLhdMsQk95lcahZp9pyHd2NgjsaSsQdJ+/H3F6+7nUTiwHmF0+yUfp6I5uVoFwEM1LYPWQ+YFfDSaZqzYty9TxwIBy57w59l74+lcx4AilhpT9yam5UfknMXdfI+ZYLK+uuqqhvcEKP+hR6","valid":true,"self_signed":true},"fingerprint_md5":"ce2473da2a3c2f6f6abd24523acd70e3","fingerprint_sha1":"8cdead6be60527f06708cd2a3b771914dcc5e927","fingerprint_sha256":"97f710a8fbec337da46bdc700df02029e1bd68abd1ccf8a1e8c61cd0db99b5bf","tbs_noct_fingerprint":"1ce4125fdc6a8fb884ca8c83e7b0e26fcddf5703ff3c4819573b9c907f33fbc0","spki_subject_fingerprint":"603db6169df03726f8f3c390a8f2e48ad749da598ea8b16befaed05c7ff62d4e","tbs_fingerprint":"1ce4125fdc6a8fb884ca8c83e7b0e26fcddf5703ff3c4819573b9c907f33fbc0","validation_level":"unknown","names":["1.2.3.4","dns1.test.com","dns2.test.com","http://watchit.com/"],"redacted":false}`,
		},
		{
			file:     "dsa_pk.cert",
			expected: `{"version":3,"serial_number":"1208925819615860693084129","signature_algorithm":{"name":"SHA1-RSA","oid":"1.2.840.113549.1.1.5"},"issuer":{"common_name":["Audkenni Secure Server CA"],"country":["IS"],"organization":["Audkenni hf."],"organizational_unit":["Secure Server CA"]},"issuer_dn":"CN=Audkenni Secure Server CA, OU=Secure Server CA, O=Audkenni hf., C=IS","validity":{"start":"2009-01-09T16:26:17Z","end":"2010-01-26T12:54:17Z","length":32992080},"subject":{"common_name":["ip.Arnasonfaktor.is"],"country":["IS"],"locality":["Reykjavik"],"province":["Iceland"],"organization":["Arnason Faktor"],"organizational_unit":["ip.arnasonfaktor.is"]},"subject_dn":"CN=ip.Arnasonfaktor.is, OU=ip.arnasonfaktor.is, O=Arnason Faktor, L=Reykjavik, ST=Iceland, C=IS","subject_key_info":{"key_algorithm":{"name":"DSA"},"dsa_public_key":{"g":"9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSo=","p":"/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAcc=","q":"l2BQjxUjC8yykrmCouuEC/BYHPU=","y":"bY8lujOuWu/IoIxz9mojYReO6rw9zsCkpblrVLuzlgui2JMI465K/1a+SzKHT/bo2K1/NbOe0UZry/jN6emSNNj/sgc5pdxYCh2c4amIeLkXDoUOOeztn19/dyLtRB7Npf7H+1Ip1LLUegSQPS6LAO80flb6ftNCRU85G7stvy8="},"fingerprint_sha256":"19ec4c6b3f515b8b2f82fa475a096c71c842c64c9ece251ef8452a6e1d8544f2"},"extensions":{"key_usage":{"digital_signature":true,"content_commitment":true,"key_encipherment":true,"data_encipherment":true,"value":15},"authority_key_id":"c21f54e3ac5dc886704ffeeeb2c7b13a44f3ea5d"},"unknown_extensions":[{"id":"2.16.840.1.113730.1.1","critical":false,"value":"AwIGQA=="}],"signature":{"signature_algorithm":{"name":"SHA1-RSA","oid":"1.2.840.113549.1.1.5"},"value":"BQc6It3YV3KDgAD6XVcRivzs/U5lYsa7tRw57jYQ3wD7HOEFqdyAi15+PledmPbGOfx0/WuF+X1pVFZCWjzQtdT20Qwe3woW3rYExkZHQMUMD9a1I3JZlRhzA5Lw6VD83C1YgJ/8MO0ka+innqRYrPDL4jLl5S1Rld8yuAUR4vo=","valid":false,"self_signed":false},"fingerprint_md5":"d7ba7aadc3b1c75cac88b4a66e5c9bde","fingerprint_sha1":"f29179add76028cf49737c46d84406ae891ec5e6","fingerprint_sha256":"d13e169153c233f1418568a64c7a5661b80064e38ee60de69fafc25a5b768782","tbs_noct_fingerprint":"e1cecad111fcb3a38c5ea2fe876d66b67aec51065f2a384003ee563209a0978c","spki_subject_fingerprint":"f984446b18e789d5349f49f1176ba148f92aee6034596fb230ae5211fb83466a","tbs_fingerprint":"e1cecad111fcb3a38c5ea2fe876d66b67aec51065f2a384003ee563209a0978c","validation_level":"unknown","names":["ip.Arnasonfaktor.is"],"redacted":false}`,
		},
		{
			file:     "ecdsa_pk.cert",
			expected: `{"version":3,"serial_number":"3371304046587445890","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["Google Internet Authority G3"],"country":["US"],"organization":["Google Trust Services"]},"issuer_dn":"CN=Google Internet Authority G3, O=Google Trust Services, C=US","validity":{"start":"2018-06-26T06:53:01Z","end":"2018-09-04T06:42:00Z","length":6047339},"subject":{"common_name":["mail.google.com"],"country":["US"],"locality":["Mountain View"],"province":["California"],"organization":["Google LLC"]},"subject_dn":"CN=mail.google.com, O=Google LLC, L=Mountain View, ST=California, C=US","subject_key_info":{"key_algorithm":{"name":"ECDSA"},"ecdsa_public_key":{"b":"WsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEs=","curve":"P-256","gx":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY=","gy":"T+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=","length":256,"n":"/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVE=","p":"/////wAAAAEAAAAAAAAAAAAAAAD///////////////8=","pub":"BLEW+n5URDCiNs4UhzvfOUkHJgwkWJVbP/Hyd6OmIUu1qoiU9IcsJZH4c8+FdIVMb7K1gwphx0Sy0mhsoEYL9EU=","x":"sRb6flREMKI2zhSHO985SQcmDCRYlVs/8fJ3o6YhS7U=","y":"qoiU9IcsJZH4c8+FdIVMb7K1gwphx0Sy0mhsoEYL9EU="},"fingerprint_sha256":"3d82c0e8c96edec5a3259e063fba0111f7916d7e0755f5e882c62e6d049a1b27"},"extensions":{"key_usage":{"digital_signature":true,"value":1},"basic_constraints":{"is_ca":false},"subject_alt_name":{"dns_names":["mail.google.com","inbox.google.com"]},"crl_distribution_points":["http://crl.pki.goog/GTSGIAG3.crl"],"authority_key_id":"77c2b8509a677676b12dc286d083a07ea67eba4b","subject_key_id":"0bc4a33fec3fa89a58d01ba2530f4774f0644dd8","extended_key_usage":{"server_auth":true},"certificate_policies":[{"id":"1.3.6.1.4.1.11129.2.5.3"},{"id":"2.23.140.1.2.2"}],"authority_info_access":{"ocsp_urls":["http://ocsp.pki.goog/GTSGIAG3"],"issuer_urls":["http://pki.goog/gsr2/GTSGIAG3.crt"]}},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"HkrBrbCHCCsur3e5qxJVHJWasboIApWUFrI8BgOq1mXr0XVz3vlOVat9CfnWQO8n/3pR9y7t0awM6uryH1jTZEdOxVfX2yCKOfjNcgWw6G09k5od5C0RyeXIoC1FZMEXd8hRSSQxuG4NljPWwAIjAMJPX9CgU1GUi0NSIT2hm1p4u8bMHizhvHqZm+aU6PtB5JUk/jJFxESLHhvUJpmWFcLM1mAlPlIvP9iZlZRlRNtkvc8PnFQoZZiJe0geTI5vNkUYvWX8QsU5NT9xWhgAxqr0Pbmbo8UmqrEltc+7ZpoUKQqHOsk7mXGuF29uJl7G9TImIq/MeLqt/p2SUCVSDg==","valid":false,"self_signed":false},"fingerprint_md5":"ed7f87bad268e667a604330850fdcca4","fingerprint_sha1":"c811986655648b871ee9b91c0b6768f362de7d69","fingerprint_sha256":"c1bd898b62dbb24b421ed0a329e47e1bc493c8185c4f34b9450514034e9ad363","tbs_noct_fingerprint":"819c0ae03795230ea4eada083ce6f371508e48b9f370fc499b0ebb01913a40b9","spki_subject_fingerprint":"e8223dca6ce0002d2a5cb3ffb276c90a5622a171282d7d80066e306080916db6","tbs_fingerprint":"819c0ae03795230ea4eada083ce6f371508e48b9f370fc499b0ebb01913a40b9","validation_level":"OV","names":["inbox.google.com","mail.google.com"],"redacted":false}`,
		},
		{
			file:     "wildcard.cert",
			expected: `{"version":3,"serial_number":"294647233722814712754417658626119973106162","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["Let's Encrypt Authority X3"],"country":["US"],"organization":["Let's Encrypt"]},"issuer_dn":"CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US","validity":{"start":"2018-07-03T06:08:13Z","end":"2018-10-01T06:08:13Z","length":7776000},"subject":{"common_name":["*.19670306.xyz"]},"subject_dn":"CN=*.19670306.xyz","subject_key_info":{"key_algorithm":{"name":"ECDSA"},"ecdsa_public_key":{"b":"szEvp+I+5+SYjgVr4/gtGRgdnG7+gUESAxQIj1ATh1rGVjmNii7RnSqFyO3T7Crv","curve":"P-384","gx":"qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3","gy":"NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f","length":384,"n":"////////////////////////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlz","p":"//////////////////////////////////////////7/////AAAAAAAAAAD/////","pub":"BF9wBueiWtjBCpYnFzZlSAPyPiEDvQmj22avvmRw1EOLz4nhqHOyiXDoHEH+49XGjf4ZYGM1WCECjKjptG6eYN8Qnnjqs5T7J7jDPo+P6GtP6P2hzT52w/Yf+nSIHuVcbQ==","x":"X3AG56Ja2MEKlicXNmVIA/I+IQO9CaPbZq++ZHDUQ4vPieGoc7KJcOgcQf7j1caN","y":"/hlgYzVYIQKMqOm0bp5g3xCeeOqzlPsnuMM+j4/oa0/o/aHNPnbD9h/6dIge5Vxt"},"fingerprint_sha256":"ba000592502c3cd301e9a69ebbee24359ddde5d5e852ff263a58f8285c140132"},"extensions":{"key_usage":{"digital_signature":true,"value":1},"basic_constraints":{"is_ca":false},"subject_alt_name":{"dns_names":["*.19670306.xyz","19670306.xyz"]},"authority_key_id":"a84a6a63047dddbae6d139b7a64565eff3a8eca1","subject_key_id":"b4314d8eadce8cffceeda5c0e8e99b75809bcf34","extended_key_usage":{"server_auth":true,"client_auth":true},"certificate_policies":[{"id":"2.23.140.1.2.1"},{"id":"1.3.6.1.4.1.44947.1.1.1","cps":["http://cps.letsencrypt.org"],"user_notice":[{"explicit_text":"This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/"}]}],"authority_info_access":{"ocsp_urls":["http://ocsp.int-x3.letsencrypt.org"],"issuer_urls":["http://cert.int-x3.letsencrypt.org/"]},"signed_certificate_timestamps":[{"version":0,"log_id":"23Sv7ssp7LH+yj5xbSzluaq7NveEcYPHXZ1PN7Yfv2Q=","timestamp":1530601693,"signature":"BAMARjBEAiBQQA3QA72QDGAxud5xgU3a14To64NYQrxjoO+2h9Z+WQIgbGm0nJ3WlrE+Mr3zJx0r1Q6qMEV1v0MPH3jpdvYL6RA="},{"version":0,"log_id":"KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=","timestamp":1530601693,"signature":"BAMARzBFAiAbHwyeNNhedTQKGL2voPrMCgvH8/gvUBlmCmY8tBiFVAIhAN6xelB/jz+pn9Uz30Yj9bcUtkk5JtsyKJO65yBmNeGv"}]},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"eTVX9Bl2qJyt76Mf6FYJwMHXlZ5OKXnBgs5DWyHl61srhisVy89MJlMU8vsJ+su7UFUqlN0yULfS/2hCKJYiZY/b+Dh4UibDxwZnYd6XmWGp+0WFObRhvQU7+OHAjcvqrSR1Y0uiKHnMB+YnM+o6WADZPyKKL38Nit+OMLMhIO5SFNYgw9XcsUR5UgZYWVMNDC77jMobsG5cF7uslfVdx8O0wmfIniVp4Awri2vDq037EnhyQQEjC/Vwc/KcKnlnElg2/s7M0fqjjkhN6J4qoF8It+teX7MATZ3lwEC7VdaCOxcS2v+z3hONE2bBKFmVMmFtIm+j4PxsF7gFEgTKEA==","valid":false,"self_signed":false},"fingerprint_md5":"7bf35fc5ecbde6b8ae46cba44fd4c2fb","fingerprint_sha1":"67ec38340211a7f00fb97a3d46955bbff3997f5c","fingerprint_sha256":"8aa4d2069c12fc0f3e1bcd3a6c5ffdd30797415370664d3b13abaa41a7706655","tbs_noct_fingerprint":"054d3f4bfae05fbab29c27277fd2795b9ae5912696214832da2a25e54878456a","spki_subject_fingerprint":"d9de57368d591fdabbb5e209e75933f227915fc1bb5a0531efa37d39003571f9","tbs_fingerprint":"c7af07c3bfc4e9fcc8fdef4e94981064a644155979c38cce618e3857c7a698a1","validation_level":"DV","names":["*.19670306.xyz","19670306.xyz"],"redacted":false}`,
		},
		{
			file:     "intermediate_ca.cert",
			expected: `{"version":3,"serial_number":"53","signature_algorithm":{"name":"SHA1-RSA","oid":"1.2.840.113549.1.1.5"},"issuer":{"common_name":["StartCom Certification Authority"],"country":["IL"],"organization":["StartCom Ltd."],"organizational_unit":["Secure Digital Certificate Signing"]},"issuer_dn":"CN=StartCom Certification Authority, OU=Secure Digital Certificate Signing, O=StartCom Ltd., C=IL","validity":{"start":"2009-01-01T06:00:00Z","end":"2019-01-01T06:00:00Z","length":315532800},"subject":{"common_name":["StartCom Extended Validation Server CA"],"country":["IL"],"organization":["StartCom Ltd."],"organizational_unit":["StartCom Certification Authority"]},"subject_dn":"CN=StartCom Extended Validation Server CA, OU=StartCom Certification Authority, O=StartCom Ltd., C=IL","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"tsPUsg93bTkr460eex85ipfFY2+Sst5C4qnVc+0bNyLLKch3WLP5UNoCwx7kZ9oDc89nv3yZmRDEpcNWTaJ1399vp5uy5y2hj2A3k8kqeiv/z4/YSZgDcfby4hryUU62iX2ZgY2CIVeV1juT9dbG2hrpgXUGlLct1GLf1jawsp6BWuyDcEZGhtpoKaTwtkIa2Fh5cKFsTL0pF4mRjlt2IMA3FUihVvhxFKje4zQTOcZ97PDghNXF3OHHsd41OcgHGV++uMuUx3QMhjDc/tkCAamXCNn5TbAPLUFN59a73jODKWbS6KqZYufRde/yMNVLxjSfLuW8O26JBhjVGVSrDQ==","length":2048},"fingerprint_sha256":"52d7a8a7feae494240aca02fde6c1f63a48208cdb7f401f7073b017cab118e24"},"extensions":{"key_usage":{"certificate_sign":true,"crl_sign":true,"value":96},"basic_constraints":{"is_ca":true,"max_path_len":0},"crl_distribution_points":["http://crl.startssl.com/sfsca.crl"],"authority_key_id":"4e0bef1aa4405ba517698730ca346843d041aef2","subject_key_id":"a1e19e4525794d06d902179282d53089722514a0","certificate_policies":[{"id":"2.5.29.32.0","cps":["http://www.startssl.com/policy.pdf","http://www.startssl.com/extended.pdf"]}],"authority_info_access":{"ocsp_urls":["http://ocsp.startssl.com/ca"],"issuer_urls":["http://aia.startssl.com/certs/ca.crt"]}},"signature":{"signature_algorithm":{"name":"SHA1-RSA","oid":"1.2.840.113549.1.1.5"},"value":"DIngqsHHtwEfKGFt5T+/yYVWRPNXnmBegIdQIfoXYOki95lgbffXQ1To0bziNOFNJ8xb+n+LfWOscI4y4Er+yduvTwbvDsoaeK5Do6ylXQrSRJmnmvjbgRnlBboUzslP9CPmI40t+jOplGNhuqVrxxg4GAdn1mXkFFMuGDrsxWTNhPNRbBfaEdJ6Ne9ATTkCCuuRs+ykRa/wkGXp0BaHeCIqDrI2aBnPrJFDIdK7CGmRLxhORh2o3iRUaUhUBhvKIsEZUn6e7HhGI826lb/ZZBhc4rxvilin7Piq4i2iuJutJVVGMoCGPimH73fIS9bJ4KOwwb43QUJY6djnhkYTqS839Jmu3uGScHDh3knFgLHmlay7Xbs9yF0NP6vjDLWqyftEIz8rXT0ZAaOnhIkc4qRpvsmBrNS+0iC9ASlbst9K8liq0M9ODaT8Yr5Zlu5o5y0RGCQNH6MOKRsDD1UL7N/cmL5JBofh3echWnNDN0R188lI1UPzOdTvdR767rzhD2YxWUPSIr+IdoD3TfNHoHX1fNlSfSPApsNYNhi1RF29PC4W/ML/OMTh3FkqGbjTeVKAAVzT1tyWOTSMiHOApQiGjHMdkN7u6lYPjN4likBMErc2wQvFdV1Sc/Hj2sTptRVjXseHhRBxWA9MwH2x+qOxOk2iyh4MaCplIofb68Q=","valid":false,"self_signed":false},"fingerprint_md5":"5dacd34e815e72e8bfc64a9edda63ca0","fingerprint_sha1":"9850463b55049f836cd63f69b30bd9e2c64d4274","fingerprint_sha256":"f0904797b5b47f1f050c3134a009887d01ff309f03b34a8250d244cb7040ee45","tbs_noct_fingerprint":"39063636c4293868327b870d4eb231d19162d7c9e270f5cbe5459ab4b61371ae","spki_subject_fingerprint":"4efa756daf72b2260d4910aa77d787d12ab3474977f578656f2f0f954b604417","tbs_fingerprint":"39063636c4293868327b870d4eb231d19162d7c9e270f5cbe5459ab4b61371ae","validation_level":"unknown","redacted":false}`,
		},
		{
			file:     "unknown_sig_alg.cert",
			expected: `{"version":3,"serial_number":"20081172477449677146523959297","signature_algorithm":{"name":"unknown_algorithm","oid":"1.3.6.1.4.1.12656.1.36"},"issuer":{"common_name":["Корневой удостоверяющий центр"],"country":["BY"],"locality":["г. Минск"],"province":["Минская"],"street_address":["ул. Советская 9"],"organization":["Министерство по налогам и сборам РБ"],"organizational_unit":["Отдел информационной безопасности и спецработы"]},"issuer_dn":"OU=Отдел информационной безопасности и спецработы, street=ул. Советская 9, L=г. Минск, ST=Минская, C=BY, O=Министерство по налогам и сборам РБ, CN=Корневой удостоверяющий центр","validity":{"start":"2005-03-02T07:57:35Z","end":"2019-12-26T21:59:59Z","length":467647344},"subject":{"common_name":["Рабочий удостоверяющий центр ЭС НДС"],"country":["BY"],"locality":["г. Минск"],"province":["Минская"],"street_address":["ул. Советская 9"],"organization":["Министерство по налогам и сборам РБ"],"organizational_unit":["Отдел информационной безопасности и спецработы"]},"subject_dn":"OU=Отдел информационной безопасности и спецработы, street=ул. Советская 9, L=г. Минск, ST=Минская, C=BY, O=Министерство по налогам и сборам РБ, CN=Рабочий удостоверяющий центр ЭС НДС","subject_key_info":{"key_algorithm":{"name":"unknown_algorithm"},"fingerprint_sha256":"d8de1ea1ae19d1760a0e0157343094c7e0d298e756601a796ec32d168f6a6d5b"},"extensions":{"key_usage":{"digital_signature":true,"key_encipherment":true,"data_encipherment":true,"key_agreement":true,"certificate_sign":true,"crl_sign":true,"value":125},"basic_constraints":{"is_ca":true},"subject_key_id":"15335de683fa3ad8d4bbaf9da23436c14d5f6837"},"unknown_extensions":[{"id":"2.5.29.1","critical":false,"value":"MIIBk4AUdZBaC5y7iZqsbDZKaaBbKFOoGWShggFrMIIBZzFDMEEGA1UEAx46BBoEPgRABD0ENQQyBD4EOQAgBEMENAQ+BEEEQgQ+BDIENQRABE8ETgRJBDgEOQAgBEYENQQ9BEIEQDFPME0GA1UECh5GBBwEOAQ9BDgEQQRCBDUEQARBBEIEMgQ+ACAEPwQ+ACAEPQQwBDsEPgQzBDAEPAAgBDgAIARBBDEEPgRABDAEPAAgBCAEETELMAkGA1UEBhMCQlkxFzAVBgNVBAgeDgQcBDgEPQRBBDoEMARPMRkwFwYDVQQHHhAEMwAuACAEHAQ4BD0EQQQ6MScwJQYDVQQJHh4EQwQ7AC4AIAQhBD4EMgQ1BEIEQQQ6BDAETwAgADkxZTBjBgNVBAseXAQeBEIENAQ1BDsAIAQ4BD0ERAQ+BEAEPAQwBEYEOAQ+BD0EPQQ+BDkAIAQxBDUENwQ+BD8EMARBBD0EPgRBBEIEOAAgBDgAIARBBD8ENQRGBEAEMAQxBD4EQgRLggxA4r1ukxR4jQAAAAE="},{"id":"2.5.29.2","critical":false,"value":"MCQwIoAPMjAwNTAzMDIwNzUyMzdagQ8yMDIwMDMwMTIxNTk1OVo="},{"id":"1.3.6.1.4.1.12656.5.4","critical":false,"value":"MCQwIoAPMjAwNTAzMDIwNzUyMzdagQ8yMDIwMDMwMjA3NTIzN1o="}],"signature":{"signature_algorithm":{"name":"unknown_algorithm","oid":"1.3.6.1.4.1.12656.1.36"},"value":"AMJt+Q1hAi6QOlCoPytnDPgPuQgIVUoOjrt0Zu/AcNg1P1iwCC/VLeQV8TE=","valid":false,"self_signed":false},"fingerprint_md5":"0c5eec266f5a07159ea462dd4105c70f","fingerprint_sha1":"e059c2c8c2bafe691a8df2b207cbe33f783d5c44","fingerprint_sha256":"69e62e352bf65ba7b7aa8db904b5c0eaa1cf160d9873f6a7d09c465d109accac","tbs_noct_fingerprint":"7cf4d80eafa8d7d7e5e6b72d1ec69df511081224aa0a2ad98600abe28b1f91f0","spki_subject_fingerprint":"4e6479164447cdbde6e35874150de7ba67927305c3c12f9acb3c2e5f493574d5","tbs_fingerprint":"7cf4d80eafa8d7d7e5e6b72d1ec69df511081224aa0a2ad98600abe28b1f91f0","validation_level":"unknown","redacted":false}`,
		},
		{
			file:     "qwac.pem",
			expected: `{"version":3,"serial_number":"202093337738244911112370","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["Buypass Class 3 CA 2"],"country":["NO"],"organization":["Buypass AS-983163327"]},"issuer_dn":"CN=Buypass Class 3 CA 2, O=Buypass AS-983163327, C=NO","validity":{"start":"2020-02-04T14:05:09Z","end":"2022-02-03T22:59:00Z","length":63104031},"subject":{"common_name":["qwac.prod.vipps.no"],"serial_number":["918713867"],"country":["NO"],"locality":["OSLO"],"organization":["VIPPS AS"],"postal_code":["0150"],"jurisdiction_country":["NO"],"organization_id":["PSDNO-FSA-918713867"]},"subject_dn":"serialNumber=918713867, organizationIdentifier=PSDNO-FSA-918713867, CN=qwac.prod.vipps.no, O=VIPPS AS, C=NO, jurisdictionCountry=NO, businessCategory=Private Organization, L=OSLO, postalCode=0150, organizationIdentifier=PSDNO-FSA-918713867, jurisdictionCountry=NO, businessCategory=Private Organization","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"pZhG4M3ej2sh+PdDZdMP6mW2w0Ulw11O6xg2NWaU4qypfggxS+HC5QM65GGyvHZh0BlVTYs1zuIQSxeylitwcoyOLpv1kZtXtvhXjGlnJJJCXOJh6g86WeWrhUxHFOQQtvtFg7ZhaYpeyldabnHcDcyxq3LVQmRL6WQwSQgEHCIlXCSI5+DCcBKr9iZYokq0kAg6jCFJojhUypv/rRYS2C3HBWtlWiw1Ln0BeJVEzXaCyQsmtX/TQb0W4O1YhGmvj7fC+P+mQh4PJqwd2mU5CGjcJWLdd664TudjU8uDiR7/VgwaCbi0m8ugcJNxvZ3/yLElj95aHY6gKG+rmciIGQ==","length":2048},"fingerprint_sha256":"7e0b4098d838ebe5238997c5418ea20b96a1f7e9b643293885197d609d09e77c"},"extensions":{"key_usage":{"digital_signature":true,"key_encipherment":true,"value":5},"basic_constraints":{"is_ca":false},"subject_alt_name":{"dns_names":["qwac.prod.vipps.no"]},"crl_distribution_points":["http://crl.buypass.no/crl/BPClass3CA2.crl"],"authority_key_id":"22302ed2fbf64bcac0b83bd204c4e972e6979b0c","subject_key_id":"a002f1a7fd4a9e9932efeebaa1a3aa1e2ee7eec5","extended_key_usage":{"server_auth":true,"client_auth":true},"certificate_policies":[{"id":"2.16.578.1.26.1.3.3","cps":["https://www.buypass.no/cps"]},{"id":"2.23.140.1.1"},{"id":"0.4.0.194112.1.4"}],"authority_info_access":{"ocsp_urls":["http://ocsp.buypass.com"],"issuer_urls":["http://crt.buypass.no/crt/BPClass3CA2.cer"]},"ct_poison":true,"cabf_organization_id":{"scheme":"PSD","country":"NO","reference":"918713867"},"qc_statements":{"ids":["0.4.0.1862.1.1","0.4.0.19495.2","0.4.0.1862.1.6","0.4.0.1862.1.5"],"parsed":{"etsi_compliance":[true],"types":[{"ids":["0.4.0.1862.1.6.3"]}],"pds_locations":[{"locations":[{"url":"https://www.buypass.no/pds/pds_en.pdf","language":"en"}]}]}}},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"C6EnzHU7tGVa2HUw0Y3KaRtgSkF3FNAsO63VRac/SZMykM60bM9nuwdy46/o01iQ+wi+P/kS5r6UYIBOwLOmv6PrMuj+nV3YhADI9/A1R4MqEjKWHzVefTXUT6vWOm7JDf2n4H3wdh/LxdfjxEn01/NcCPh+HEgatldcoXpnirVKctO2Kgg5dD2uLWtPQixr2aJQx+4wALCBG7cwKmp0M9CLJv35+O2/1dMwhm95NfpcX6t53F7M9720fTeFTYALX1jdN2SxA7VyHqhkc0poTNtKtutRkMMWkwcDSz/FD0NMjJdsaVIJ+bdB7gh7JT1hd4CBJDKRhNRq9aSGGIcEeQ==","valid":false,"self_signed":false},"fingerprint_md5":"ed91f4dc129bb1e645e36454b4955fd6","fingerprint_sha1":"f1b7533029586920ee56df926bc59dcd8cfa3630","fingerprint_sha256":"f42775eeb4baa39ab4ba0e3a37ee2f30a41267274ea20a75ae2721cae39f9a83","tbs_noct_fingerprint":"cff7cb3009a22b725e4d3d71762c377cbdefd196cff2712a0893e2c29870b320","spki_subject_fingerprint":"b4e3dff7dbac7fa5744f916ddaac9bb7ac09f6914c523d8cd356b543b621802c","tbs_fingerprint":"e5d2338b23acb820d285a04b800aa4f9fc162c8c919cb2b957f2b2209848a0b2","validation_level":"EV","names":["qwac.prod.vipps.no"],"redacted":false}`,
		},
		{
			file:     "etsi_qc.pem",
			expected: `{"version":3,"serial_number":"9591198274709138036589902159","signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"issuer":{"common_name":["Development Sub CA"],"country":["PK"],"organization":["Development"]},"issuer_dn":"CN=Development Sub CA, O=Development, C=PK","validity":{"start":"2019-09-25T09:37:57Z","end":"2029-10-26T09:37:57Z","length":318297600},"subject":{"common_name":["Muhammad Bilal Ashraf"],"serial_number":["578611675"],"country":["PK"],"organization":["Development"],"given_name":["Muhammad Bilal"],"surname":["Ashraf"]},"subject_dn":"CN=Muhammad Bilal Ashraf, SN=Ashraf, GN=Muhammad Bilal, serialNumber=578611675, O=Development, C=PK, SN=Ashraf, GN=Muhammad Bilal","subject_key_info":{"key_algorithm":{"name":"RSA"},"rsa_public_key":{"exponent":65537,"modulus":"2HPVolNvA0qVuwXPcXIdra/W/VOLzx5RyRjAHUC8ssYKPLJ5rNjUcAFrIMRBELVw1B+Sr3/671cDsh12nFkO4KfCpprvG9gpV2yLZPNhpUPqxpbXa6H6VQv4PYNHuf75kPJzyn2dkhw/RGNfiN9b/qM4LSxHzlrOe+gjN7uSaLEctr16v7lu650lbNC29XfG9FuRKeHAB04WoFtge6P3XwvRkHTVvcUjx0XSRD3Fbcvi/SqKZStFLN382Xp/uA7S+kX0eVHHyIgQyEydOq5lI1mTRCsJn0vOXav2YgZiHGvpDMzXPz/j/iAFblLmGeNFRUQDIrwTYUEfdGjBGOAlVw==","length":2048},"fingerprint_sha256":"bc898e576ca5b03513505d6433e91b4ada07f86a6ce3412d088db9580b13500e"},"extensions":{"key_usage":{"digital_signature":true,"content_commitment":true,"value":3},"basic_constraints":{"is_ca":false},"subject_alt_name":{"email_addresses":["bilal.ashraf@gmail.com"]},"crl_distribution_points":["http://dev.com/ca.crl"],"authority_key_id":"30cd83a736aca535ff211b37406eb2cf5f1c032f","subject_key_id":"5e3b7f1de8d5587eee26b3c792e65ac10e5fbb9d","extended_key_usage":{"email_protection":true},"certificate_policies":[{"id":"1.3.7.8.9","cps":["https://www.dev.com/repository/"]}],"authority_info_access":{"ocsp_urls":["http://dev.com/ocsp"],"issuer_urls":["http://dev.com/ca.crt"]},"qc_statements":{"ids":["0.4.0.1862.1.1","0.4.0.1862.1.3","0.4.0.1862.1.2","0.4.0.1862.1.4","0.4.0.1862.1.5","0.4.0.1862.1.6"],"parsed":{"etsi_compliance":[true],"sscd":[true],"types":[{"ids":["0.4.0.1862.1.6.1","0.4.0.1862.1.6.2","0.4.0.1862.1.6.3"]}],"limit":[{"currency":"EURO","amount":10,"exponent":2}],"pds_locations":[{"locations":[{"url":"https://dev.com/pds/en/pds.pdf","language":"en"}]}],"retention_period":[10]}}},"signature":{"signature_algorithm":{"name":"SHA256-RSA","oid":"1.2.840.113549.1.1.11"},"value":"DyWYTIzvGbzIbUbfe0mHSNxjoacuhWWQLhyX/UfHZ5hdYL7osIvwvWu81hGiGK9Eo0279W0YexJ4qp90YIzG8kjKvK7XIbFLmYnCf7+8sXHcvH9w/b8W11cTWmC2+xuYgxCWvHkGwWVpEpZlkDc+YYjilUVQ7wIcingpT98Tek36RIZ8mcNqkXUTrCaWt9Ra4h732J87MSWydifEMYUi+fSKttw7cjBzf6Q5XFkWY0uQtY087EIRldezwa9CZASStaEVzQ7UTsOzLSbmYEQzKK8siO6Z+RjV86ZU47uSZ2cC++/SQBufAQ0Ch/tnN2O3vACfA30QhQblWHe9Wd4taA==","valid":false,"self_signed":false},"fingerprint_md5":"173780910e4430a16d0e7a4ed6667b9f","fingerprint_sha1":"ce69f32ca243df47f6fccb985d6d340b15d5a827","fingerprint_sha256":"a5885ab12e6260345007884baa9f1ca7343719d80381e3a7653be314e80dea34","tbs_noct_fingerprint":"5753c966f66d7db686320109cc4f79553fa25aa45917b8326aab7e9a42507f3b","spki_subject_fingerprint":"af9c1632cdf9bc7b1041ca90006c6956b44cfc0b224ff0c19228b980e8e1b280","tbs_fingerprint":"5753c966f66d7db686320109cc4f79553fa25aa45917b8326aab7e9a42507f3b","validation_level":"unknown","redacted":false}`,
		},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			path := testdataPrefix + test.file
			certBytes, err := ioutil.ReadFile(path)
			require.NoError(t, err)
			p, _ := pem.Decode(certBytes)
			require.NoError(t, err)
			c, err := ParseCertificate(p.Bytes)
			require.NoError(t, err)
			jsonBytes, err := json.Marshal(c)
			if len(test.expected) > 0 {
				require.NoError(t, err)
			}
			jsonString := string(jsonBytes)
			assert.Equal(t, test.expected, jsonString)
			backToCert := Certificate{}
			err = json.Unmarshal(jsonBytes, &backToCert) // should fail
			assert.Error(t, err, "Expected UnmarshalJSON to fail, should not be used")
			jsonWithRaw := JSONCertificateWithRaw{
				Raw: p.Bytes,
			}
			_, err = jsonWithRaw.ParseRaw()
			assert.NoError(t, err)
		})
	}
}

func TestKeyUsageJSON(t *testing.T) {
	tests := []struct {
		k                       KeyUsage
		expectDigitalSignature  bool
		expectContentCommitment bool
		expectKeyEncipherment   bool
		expectDataEncipherment  bool
		expectKeyAgreement      bool
		expectCertificateSign   bool
		expectCrlSign           bool
		expectEncipherOnly      bool
		expectDecipherOnly      bool
	}{
		{
			k:                      KeyUsageDigitalSignature,
			expectDigitalSignature: true,
		},
		{
			k:                     KeyUsageCertSign + KeyUsageCRLSign,
			expectCertificateSign: true,
			expectCrlSign:         true,
		},
		{
			k:                  KeyUsageEncipherOnly,
			expectEncipherOnly: true,
		},
		{
			k:                  KeyUsageDecipherOnly,
			expectDecipherOnly: true,
		},
		{
			k:                  KeyUsageKeyAgreement,
			expectKeyAgreement: true,
		},
	}
	for i, test := range tests {
		j, _ := json.Marshal(test.k)
		jsonString := string(j)
		if test.expectDigitalSignature {
			if !strings.Contains(jsonString, `"digital_signature":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectContentCommitment {
			if !strings.Contains(jsonString, `"content_commitment":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectKeyEncipherment {
			if !strings.Contains(jsonString, `"key_encipherment":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectDataEncipherment {
			if !strings.Contains(jsonString, `"data_encipherment":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectKeyAgreement {
			if !strings.Contains(jsonString, `"key_agreement":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectCertificateSign {
			if !strings.Contains(jsonString, `"certificate_sign":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectCrlSign {
			if !strings.Contains(jsonString, `"crl_sign":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectEncipherOnly {
			if !strings.Contains(jsonString, `"encipher_only":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		if test.expectDecipherOnly {
			if !strings.Contains(jsonString, `"decipher_only":true`) {
				t.Errorf("%d: flags set improperly", i)
				continue
			}
		}
		var backToKeyUsage KeyUsage
		err := json.Unmarshal(j, &backToKeyUsage)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		if backToKeyUsage != test.k {
			t.Errorf("%d: Unmarshal did not preserve value", i)
		}
	}
}

func TestSignatureAlgorithmJSON(t *testing.T) {
	algs := []SignatureAlgorithm{UnknownSignatureAlgorithm, MD2WithRSA, MD5WithRSA, SHA1WithRSA, SHA256WithRSA, SHA384WithRSA, SHA512WithRSA, DSAWithSHA1, DSAWithSHA256, ECDSAWithSHA1, ECDSAWithSHA256, ECDSAWithSHA384, ECDSAWithSHA512, SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS}
	for i, alg := range algs {
		j, err := json.Marshal(&alg)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		var backToAlg SignatureAlgorithm
		err = json.Unmarshal(j, &backToAlg)
		if alg == UnknownSignatureAlgorithm {
			if err == nil {
				t.Errorf("%d: Should fail on unrecognized algorithm", i)
			}
		} else {
			if err != nil {
				t.Errorf("%d: %s", i, err.Error())
			}
			if strings.Compare(backToAlg.String(), alg.String()) != 0 {
				t.Errorf("%d: Unmarshal did not preserve value", i)
			}
		}
	}
}

func TestPublicKeyAlgorithmJSON(t *testing.T) {
	algs := []PublicKeyAlgorithm{UnknownPublicKeyAlgorithm, RSA, DSA, ECDSA}
	for i, alg := range algs {
		j, err := json.Marshal(&alg)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		var backToAlg PublicKeyAlgorithm
		err = json.Unmarshal(j, &backToAlg)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		if backToAlg != alg {
			t.Errorf("%d: Unmarshal did not preserve value", i)
		}
	}
}

func TestValidityJSON(t *testing.T) {
	preEpoch, err := time.Parse("20060102150405", "19040824000000")
	if err != nil {
		t.Error(err)
	}
	tests := []validity{
		{
			NotBefore: time.Unix(1400000000, 0),
			NotAfter:  time.Unix(1500000000, 0),
		},
		{
			NotBefore: time.Unix(1000000000, 0),
			NotAfter:  time.Unix(1700000000, 0),
		},
		{
			NotBefore: preEpoch,
			NotAfter:  preEpoch,
		},
		{
			NotBefore: kMinTime,
			NotAfter:  kMaxTime,
		},
		{
			NotBefore: kMaxTime,
			NotAfter:  kMinTime,
		},
	}
	for i, v := range tests {
		j, err := json.Marshal(&v)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		var backToValidity validity
		err = json.Unmarshal(j, &backToValidity)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		if !(backToValidity.NotAfter.Equal(v.NotAfter) && backToValidity.NotBefore.Equal(v.NotBefore)) {
			t.Errorf("%d: Unmarshal did not preserve value", i)
		}
	}
}

func TestGeneralSubTreeIPJSON(t *testing.T) {
	tests := []GeneralSubtreeIP{
		{
			Data: net.IPNet{
				IP:   net.IPv4(192, 168, 1, 1),
				Mask: net.CIDRMask(16, 32),
			},
		},
		{
			Data: net.IPNet{
				IP:   net.IPv4(127, 1, 1, 1),
				Mask: net.CIDRMask(24, 32),
			},
		},
	}
	for i, tree := range tests {
		j, err := json.Marshal(&tree)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		var backToGeneralSubtreeIP GeneralSubtreeIP
		err = json.Unmarshal(j, &backToGeneralSubtreeIP)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
		}
		if strings.Compare(backToGeneralSubtreeIP.Data.String(), tree.Data.String()) != 0 {
			t.Errorf("%d: Unmarshal did not preserve value", i)
		}
	}
}
