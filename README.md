# BurpSuite Extension - Asset History[<img src="https://i1.wp.com/redhuntlabs.com/wp-content/uploads/2020/05/RedHunt-Logo-Without-Text-Dark.png?w=512&ssl=1" align="right" width="100">](https://redhuntlabs.com/)
Burp Suite extension to identify the historic URLs of the domains in scope from WayBackMachine. Refer to our blog [Asset History using Burp Suite](https://redhuntlabs.com/blog/asset-history-burp-extension.html) for more details.

**[`To know more about our Attack Surface Management platform, check out NVADR.`](https://redhuntlabs.com/nvadr)**

# Description
The extension acts as a passive scanner which extracts the domain(s) that are in scope, identifies their historic URLs from [WayBackMachine](http://web.archive.org/) and lists them under the issues section. The URLs can be easily copied from their and tested further for security issues. 

# Setup
- Setup the python environment by providing the [jython.jar](https://www.jython.org/downloads.html) file in the 'Options' tab under 'Extender' in Burp Suite.
- Download the [extension](https://github.com/redhuntlabs/BurpSuite-Asset_History/archive/master.zip).
- In the 'Extensions' tab under 'Extender', select 'Add'.
- Change the extension type to 'Python'.
- Provide the path of the file ‘Asset_History.py’ and click on 'Next'.
- Add the target domain/URL in Scope.

<kbd><img src="https://github.com/redhuntlabs/BurpSuite-Asset_History/blob/master/Screenshots/Add%20Extension.jpg" width="420" height="275"></kbd> <kbd><img src="https://github.com/redhuntlabs/BurpSuite-Asset_History/blob/master/Screenshots/Add%20Domain%20to%20Scope.jpg" width="420" height="275"></kbd>

# Usage
- Add a URL to the 'Scope' under the 'Target' tab. The extension will identify historic URLs for it. 

<kbd><img src="https://github.com/redhuntlabs/BurpSuite-Asset_History/blob/master/Screenshots/Asset%20History.jpg" width="420" height="275"></kbd> 

# Requirements
- [Jython 2.7.0](https://www.jython.org/download)
- [Burp Suite Pro v2020.6](https://portswigger.net/burp) [Not tested on older version, however it should work fine]

# Code Credits
A large portion of the base code has been taken from the following sources:
- [OpenSecurityResearch CustomPassiveScanner](https://github.com/OpenSecurityResearch/CustomPassiveScanner)
- [PortSwigger example-scanner-checks](https://github.com/PortSwigger/example-scanner-checks)
- [BurpSuite Extension - Asset Discover](https://github.com/redhuntlabs/BurpSuite-Asset_Discover)

# To-Do:
- [ ] Add AlienVault Open Threat Exchange
- [ ] Add Domain History
- [ ] Add IP History

# License
The project is available under MIT license, see [LICENSE](https://github.com/redhuntlabs/BurpSuite-Asset_History/blob/master/LICENSE) file.
