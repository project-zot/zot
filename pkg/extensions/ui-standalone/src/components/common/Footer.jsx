import React from 'react';
import LABELS from '../../strings';

class Footer extends React.Component {
    render() {
        // according to CUI The links in this footer are the minimum required by Cisco legal.
        return (
            <footer className="footer footer--basic footer--compressed">
                <div className="footer__links">
                    <ul className="list">
                        <li><a href="https://www.cisco.com/c/en/us/about/contact-cisco.html" target="_blank" rel="noopener noreferrer">{LABELS.contacts}</a></li>
                        <li><a href="https://secure.opinionlab.com/ccc01/o.asp?id=jBjOhqOJ" target="_blank" rel="noopener noreferrer">{LABELS.feedback}</a></li>
                        <li><a href="https://www.cisco.com/c/en/us/about/help.html" target="_blank" rel="noopener noreferrer">{LABELS.help}</a></li>
                        <li><a href="http://www.cisco.com/c/en/us/about/sitemap.html" target="_blank" rel="noopener noreferrer">{LABELS.siteMap}</a></li>
                        <li><a href="https://www.cisco.com/c/en/us/about/legal/terms-conditions.html" target="_blank" rel="noopener noreferrer">{LABELS.termAndConditions}</a></li>
                        <li><a href="https://www.cisco.com/c/en/us/about/legal/privacy-full.html" target="_blank" rel="noopener noreferrer">{LABELS.privacyStatement}</a></li>
                        <li><a href="https://www.cisco.com/c/en/us/about/legal/privacy-full.html#cookies" target="_blank" rel="noopener noreferrer">{LABELS.cookiePolicy}</a></li>
                        <li><a href="https://www.cisco.com/c/en/us/about/legal/trademarks.html" target="_blank" rel="noopener noreferrer">{LABELS.trademarks}</a></li>
                    </ul>
                </div>
            </footer>
        );
    }
}

export {Footer};
