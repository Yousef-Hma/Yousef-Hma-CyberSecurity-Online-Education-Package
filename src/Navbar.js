import React from 'react'
import {Navbar, Nav, NavDropdown} from 'react-bootstrap'
import CV from './Attachments/Yousef_Hazem_CV.pdf'
import Thesis from './Attachments/Thesis.pdf'

export default function Navbarr() {
    return (
        <Navbar collapseOnSelect expand="lg" bg="dark" variant="dark">
            <Navbar.Brand href="/">CyberSecurity Educational Package</Navbar.Brand>
            <Navbar.Toggle aria-controls="responsive-navbar-nav" />
            <Navbar.Collapse id="responsive-navbar-nav" style={{paddingLeft:"3.5%"}}>
                <Nav className="mr-auto">
                <NavDropdown title="Related Articles" id="collasible-nav-dropdown">
                <NavDropdown.Item href={Thesis} target="_blank">Author's Thesis</NavDropdown.Item>
                <NavDropdown.Divider />
                        <NavDropdown.Item href="http://phrack.org/issues/49/14.html" target="_blank">Aleph One's Article</NavDropdown.Item>
                        <NavDropdown.Item href="http://flint.cs.yale.edu/cs421/papers/x86-asm/asm.html" target="_blank">x86 Assembly Guide</NavDropdown.Item>
                        <NavDropdown.Item href="https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/" target="_blank">Shellcode Guide</NavDropdown.Item>
                    </NavDropdown>
                    <Nav.Link href="/KnowledgeBase">Knowledge Base</Nav.Link>
                    <Nav.Link href="/ShellcodeGenerator">Shellcode Generator</Nav.Link>
                    <Nav.Link href="/CodeReviewer">Code Reviewer</Nav.Link>
                    <NavDropdown title="About Author" id="collasible-nav-dropdown">
                        <NavDropdown.Item href="https://www.linkedin.com/in/yousef-abdalla-390504184/" target="_blank">LinkedIn</NavDropdown.Item>
                        {/* <NavDropdown.Item href={CV} target="_blank">Online Portfolio</NavDropdown.Item> */}
                        <NavDropdown.Item href={CV} target="_blank">CV-Résumé</NavDropdown.Item>
                        <NavDropdown.Divider />
                        <NavDropdown.Item href="mailto:yousef.hma@gmail.com">Contact Form</NavDropdown.Item>
                    </NavDropdown>
                </Nav>
            </Navbar.Collapse>
        </Navbar>
    )
}