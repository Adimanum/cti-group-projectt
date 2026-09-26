/*
   Tycoon2FA AiTM phishing kit - detection rules
   Author : CS-2426 group project (Dilnaz Estaikyzy, Ademi Akmaganbet)
   Date   : 2026-09-26
   Based on publicly documented kit traits (Sekoia 2024, Trustwave SpiderLabs 2025).
   Written by the group; tested with YARA 4.5.2 against the test corpus in this folder
   (see yara_test_results.txt).
*/

rule Tycoon2FA_Landing_Page_Artifacts
{
    meta:
        description = "HTML landing page that loads Tycoon2FA-style resources and opens a WebSocket relay"
        author      = "CS-2426 group project"
        date        = "2026-09-26"
        reference   = "https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit/"
        mitre       = "T1566.002, T1557"
        scope       = "HTML page (not the separate JS file)"

    strings:
        $js_name     = /myscr[0-9]{6}\.js/ ascii wide nocase
        $css_godaddy = "pages-godaddy.css" ascii wide nocase
        $css_okta    = "pages-okta.css" ascii wide nocase
        $ws          = "new WebSocket(" ascii wide
        $html        = "<html" ascii wide nocase

    condition:
        filesize < 2MB and $html and
        2 of ($js_name, $css_godaddy, $css_okta, $ws)
}

rule Tycoon2FA_Invisible_Unicode_JS
{
    meta:
        description = "JavaScript hidden as long runs of Hangul Filler characters (U+3164 / U+FFA0, UTF-8) decoded through a Proxy object"
        author      = "CS-2426 group project"
        date        = "2026-09-26"
        reference   = "https://trustwave.com/en-us/resources/blogs/spiderlabs-blog/tycoon2fa-new-evasion-technique-for-2025"
        mitre       = "T1027 (Obfuscated Files or Information)"

    strings:
        // 64+ consecutive filler characters = at least 8 hidden bytes of code
        $filler_run = /(\xE3\x85\xA4|\xEF\xBE\xA0){64,}/
        $proxy      = "new Proxy(" ascii

    condition:
        filesize < 5MB and $filler_run and $proxy
}
