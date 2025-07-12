import unittest
from unittest.mock import patch, MagicMock, mock_open
import builtwith
import whois
import ssl
import socket
import subprocess
import requests
from Enumeration import WebEnumerator

class TestWebEnumerator(unittest.TestCase):
    def setUp(self):
        self.print_patcher = patch('builtins.print')
        self.mock_print = self.print_patcher.start()
        self.url = "https://example.com"
        self.ports = "80"
        self.enumerator = WebEnumerator(self.url, self.ports, extract_emails=True)
        self.enumerator.stop_flag = False

    def tearDown(self):
        self.print_patcher.stop()

    def test_get_domain(self):
        domain = self.enumerator.get_domain()
        self.assertEqual(domain, "example.com")

    @patch('builtwith.builtwith')
    @patch("builtins.open", new_callable=mock_open, read_data="django\nreact\n")
    def test_detect_technologies(self, mock_file, mock_builtwith):
        mock_builtwith.return_value = {
            "framework": ["Django", "ReactJS"],
            "web-servers": ["nginx"]
        }
        techs = self.enumerator.detect_technologies()
        self.assertIn("Django", techs)
        self.assertNotIn("ReactJS", techs)

    @patch("subprocess.run")
    @patch("builtins.open", new_callable=mock_open)
    def test_search_exploits_found(self, mock_file, mock_subproc):
        mock_subproc.return_value.stdout = "Exploit found\n"
        self.enumerator.search_exploits("nginx")
        mock_file().write.assert_called_with("Exploit found\n")

    @patch("subprocess.run")
    @patch("builtins.open", new_callable=mock_open)
    def test_search_exploits_not_found(self, mock_file, mock_subproc):
        mock_subproc.return_value.stdout = ""
        self.enumerator.search_exploits("fake_tech")
        mock_file().write.assert_called_with("No public exploits found.\n")

    @patch("requests.get")
    @patch("builtins.open", new_callable=mock_open, read_data="test\n")
    def test_fuzz_generic(self, mock_file, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_requests.return_value = mock_resp

        def formatter(x):
            return (f"Line {x}\n", f"https://example.com/{x}")

        self.enumerator.fuzz_generic("fake_wordlist.txt", "output.txt", formatter)

        handle = mock_file()
        handle.write.assert_called()

    def test_is_valid_email(self):
        valid = "test@example.com"
        invalid = "test@@example..com"
        self.assertTrue(self.enumerator.is_valid_email(valid))
        self.assertFalse(self.enumerator.is_valid_email(invalid))

    @patch("requests.get")
    @patch("builtins.open", new_callable=mock_open)
    def test_extract_emails(self, mock_file, mock_requests):
        html = "Contact us at test@example.com or spam@bad..domain"
        mock_requests.return_value.text = html
        self.enumerator.extract_emails("https://example.com")
        mock_file().write.assert_called_with("test@example.com\n")

    @patch("whois.whois")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_whois_record_success(self, mock_file, mock_whois):
        mock_whois.return_value = MagicMock(
            registrar="Registrar Inc.",
            creation_date="2020-01-01",
            expiration_date="2023-01-01",
            name_servers=["ns1.example.com", "ns2.example.com"]
        )
        self.enumerator.get_whois_record()
        mock_file().write.assert_called()

    @patch("whois.whois", side_effect=whois.parser.PywhoisError)
    def test_get_whois_record_failure(self, mock_whois):
        self.enumerator.get_whois_record()

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_ssl_certificate(self, mock_file, mock_socket, mock_ssl_ctx):
        mock_sslsock = MagicMock()
        mock_sslsock.getpeercert.return_value = {"subject": "cert"}
        mock_socket().__enter__.return_value = MagicMock()
        mock_ssl_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_sslsock
        self.enumerator.get_ssl_certificate()
        mock_file().write.assert_called()

    @patch("socket.gethostbyname")
    @patch("socket.socket")
    @patch("builtins.open", new_callable=mock_open)
    def test_port_scan(self, mock_file, mock_socket, mock_gethost):
        mock_gethost.return_value = "1.2.3.4"
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect.return_value = None
        with patch("socket.getservbyport", return_value="http"):
            self.enumerator.port_scan()

    def test_run_method_calls(self):
        with patch.object(self.enumerator, "detect_technologies", return_value=["nginx"]) as dtech, \
             patch.object(self.enumerator, "search_exploits") as sexp, \
             patch.object(self.enumerator, "fuzz_directories") as fd, \
             patch.object(self.enumerator, "fuzz_subdomains") as fs, \
             patch.object(self.enumerator, "fuzz_files") as ff, \
             patch.object(self.enumerator, "dns_enum") as dns_enum, \
             patch.object(self.enumerator, "port_scan") as pscan, \
             patch.object(self.enumerator, "get_whois_record") as whois_rec, \
             patch.object(self.enumerator, "get_ssl_certificate") as ssl_cert:
            self.enumerator.run()
            dtech.assert_called_once()
            sexp.assert_called()
            fd.assert_called_once()
            fs.assert_called_once()
            ff.assert_called_once()
            dns_enum.assert_called_once()
            pscan.assert_called_once()
            whois_rec.assert_called_once()
            ssl_cert.assert_called_once()

if __name__ == "__main__":
    unittest.main()
