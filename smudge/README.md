<div id="top"></div>


<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/activecm/passer">
    <img src="images/smudge.png" alt="Logo" width="600" height="600">
  </a>

<h3 align="center">Smudge</h3>

  <p align="center">
    project_description
    <br />
    <a href="https://github.com/activecm/passer"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/activecm/passer">View Demo</a>
    ·
    <a href="https://github.com/activecm/passer/issues">Report Bug</a>
    ·
    <a href="https://github.com/activecm/passer/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#signatures">Signatures</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#logo">Logo</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

<a href="https://github.com/activecm/passer">
    <img src="images/smudge_screenshot.png" alt="Screenshot" width="900" height="300">
</a>



<p align="right">(<a href="#top">back to top</a>)</p>



### Built With

* [Python](https://www.python.org/)
* [Scapy](https://scapy.net/)


<p align="right">(<a href="#top">back to top</a>)</p>


### Prerequisites

Ensure that scapy is installed:
[Scapy Install](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x/)

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage

Smudge is a component of Active Countermeasure's Passer. It can be called from the command line via the following arguments:

<a> `-p, --passive_fingerprinting`<br/>Enables Smudge.</a><br/>
<a> `-d, --devel`<br/>Creates signatures and outputs them. </a><br/>
<a> `-j, --json`<br/>Specifies local file to load signatures from. </a><br/>

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- Signatures -->
## Create Your Own Signatures

Currently **SMUDGE** only detects signatures from TCP SYN packets. TCP SYN packets are passively sniffed with **Passer**. If **SMUDGE** is enabled, the a signature is generated and it is searched for in the database. Signatures need to be created from known sources to add additional entries into our database.

A signature for a TCP SYN packet look like this:

```
sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
```

---

### Version
`ver` - signature for IPv4 ('4'), IPv6 ('6'), or both ('*').

---

### Initial Time to Live
`ittl` - initial TTL used by the OS. Almost all operating systems use 64, 128, or 255; ancient versions of Windows sometimes used 32, and several obscure systems sometimes resort to odd values such as 60.

---

### Options Length
`olen` - length of IPv4 options or IPv6 extension headers. Usually zero for normal IPv4 traffic; always zero for IPv6 due to the limitations of libpcap/winpcap/npcap. 

---

### Maximum Segment Size
`mss`  - maximum segment size, if specified in TCP options. Special value of '*' can be used to denote that MSS varies depending on the parameters of sender's network link, and should not be a part of the signature. In this case, MSS will be used to guess the type of network hookup according to the [mtu] rules.

--- 

### Window Size
`wsize` - window size. Can be expressed as a fixed value, but many operating systems set it to a multiple of MSS or MTU, or a multiple of some random integer. **SMUDGE** allows notation such as 'mss*4', 'mtu*4', or '%8192' to be used. Wilcard ('*') is possible too.

---

### Window Scaling Factor
`scale` - window scaling factor, if specified in TCP options. Fixed value or '*'.

---

### Options Layout
`olayout` - comma-delimited layout and ordering of TCP option. This is a longer string and is comprised of several values.
 
| Item        | Description                                             | 
| ----------- | -----------                                             |
| eol+n       | explicit end of options, followed by n bytes of padding | 
| nop         | no-op option                                            |
| mss         | maximum segment size                                    |
| ws          | window scaling                                          |
| sok         | selective ACK permitted                                 |
| sack        | selective ACK (should not be seen)                      |
| ts          | timestamp                                               |
| ?n          | unknown option ID n                                     |

---

### Quirks
`quirks`     - comma-delimited properties and quirks observed in IP or TCP headers.

The definition of a quirk is a `peculiar behavioral habit`. When quirks are observed in IP/TCP headers, it is import to ensure that they continue to be observed. Quirks may not present themselves the same way everytime. Do your best to find items on this list that offer repeatability.

| Item        | Description                                             | 
| ----------- | -----------                                             |
| df          | "don't fragment" set (probably PMTUD); ignored for IPv6 | 
| id+         | DF set but IPID non-zero; ignored for IPv6              |
| id-         | DF not set but IPID is zero; ignored for IPv6           |
| ecn         | explicit congestion notification support                |
| 0+          | "must be zero" field not zero; ignored for IPv6         |
| flow        | non-zero IPv6 flow ID; ignored for IPv4                 |
|             |                                                         |
| seq-        | sequence number is zero                                 |
| ack+        | ACK number is non-zero, but ACK flag not set            |
| ack-        | ACK number is zero, but ACK flag set                    |
| uptr+       | URG pointer is non-zero, but URG flag not set           |
| urgf+       | URG flag used                                           |
| pushf+      | PUSH flag used                                          |
|             |                                                         |
| ts1-        | own timestamp specified as zero                         |
| ts2+        | non-zero peer timestamp on initial SYN                  |
| opt+        | trailing non-zero data in options segment               |
| exws        | excessive window scaling factor (> 14)                  |
| bad         | malformed TCP options                                   |

---

### Payload Size Classification
`pclass`     - payload size classification: '0' for zero, '+' for non-zero, '*' for any. The packets we fingerprint right now normally have no payloads, but some corner cases exist.

---

This repository includes a tool called "sig_gen.py". This tool can be leveraged to create signatures from known sources. Signatures are created in the same format as p0f and information about the signature format can be found here [p0f](https://github.com/p0f/p0f).

Signatures are stored in a Github Repository maintained by Active COuntermeasures that can be found here [tcp-sig-json](https://github.com/activecm/tcp-sig-json).
Adding a new signature is as easy creating a new pull request.

<p align="right">(<a href="#top">back to top</a>)</p>






<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

David Quartarolo - [@d_quartarolo](https://twitter.com/d_quartarolo) - david@activecountermeasures.com

Project Link: [https://github.com/activecm/passer](https://github.com/activecm/passer)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [Bill Stearns](https://github.com/william-stearns)
  Bill has been working with me on this from day 1. Checkout Bill's Site [here](http://www.stearns.org/)


<p align="right">(<a href="#top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/activecm/passer
[contributors-url]: https://github.com/github_username/repo_name/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/activecm/passer
[forks-url]: https://github.com/github_username/repo_name/network/members
[stars-shield]: https://img.shields.io/github/stars/activecm/passer
[stars-url]: https://github.com/activecm/passer/stargazers
[issues-shield]: https://img.shields.io/github/issues/activecm/passer
[issues-url]: https://github.com/github_username/repo_name/issues
[license-shield]: https://img.shields.io/github/license/activecm/passer
[license-url]: https://github.com/github_username/repo_name/blob/master/LICENSE.txt
[product-screenshot]: images/screenshot.png