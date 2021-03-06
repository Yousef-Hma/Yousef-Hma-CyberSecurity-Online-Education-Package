import { FaGithub } from 'react-icons/fa'


const Footer = () => {
    return (
                <div className="footer">
                    <p style={{marginBottom:"0px"}}>&copy; 2021 CyberSecurity Educational Package! All content is publicly accessible on <a href="https://github.com/Yousef-Hma/Yousef-Hma-CyberSecurity-Online-Education-Package" target="_blank" rel="noopener noreferrer">GitHub <FaGithub /></a> and is subject to Copyright &copy;</p>
                    <p class="pull-right">
                        <a href="#top" id="back-top">
                            Back to Top				</a>
                    </p>
                    <br/>
                </div>
     );
}

export default Footer;


