import React from 'react';
import PropTypes from 'prop-types';
import { fade, withStyles } from '@material-ui/core/styles';
import TreeView from '@material-ui/lab/TreeView';
import TreeItem from '@material-ui/lab/TreeItem';
import Collapse from '@material-ui/core/Collapse';
import ReactPlayer from 'react-player';
import { useSpring, animated } from 'react-spring/web.cjs'; // web.cjs is required for IE 11 support
import README1 from './Attachments/KnowledgeBaseFiles/KnowledgeBase/README.txt'
import SyntaxATnT from './Attachments/KnowledgeBaseFiles/KnowledgeBase/Basics of Assembly/Assembly Syntax/AT&T Syntax.txt'
import SyntaxIntel from './Attachments/KnowledgeBaseFiles/KnowledgeBase/Basics of Assembly/Assembly Syntax/Intel Syntax.txt'
import EgInlineAssm from './Attachments/KnowledgeBaseFiles/KnowledgeBase/Basics of Assembly/Example Inline Assembly Program.txt'
import AssmInstructions from './Attachments/KnowledgeBaseFiles/KnowledgeBase/Basics of Assembly/Assembly Instructions.txt'
import arwin from './Attachments/KnowledgeBaseFiles/Programs/arwin.txt'
import InlineAssm from './Attachments/KnowledgeBaseFiles/Programs/Inline_Assembly.txt'
import Shellcode_Basecode from './Attachments/KnowledgeBaseFiles/Programs/Shellcode_Basecode.txt'
import Sender from './Attachments/KnowledgeBaseFiles/Programs/Sender.txt'
import Receiver from './Attachments/KnowledgeBaseFiles/Programs/Receiver.txt'
import Networked_Basecode from './Attachments/KnowledgeBaseFiles/Programs/Networked_Basecode.txt'
import SimpleProg from './Attachments/KnowledgeBaseFiles/Programs/SimpleProg.txt'
import VulnerableProg from './Attachments/KnowledgeBaseFiles/Programs/VulnProg.txt'
import Thesis from './Attachments/Thesis.pdf'
import { FiFileText } from 'react-icons/fi'
import { VscFolder } from 'react-icons/vsc'
import { VscFolderOpened } from 'react-icons/vsc'
import ShellcodeExploit_MsgBox from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/ShellcodeExploit_MsgBox.txt'
import Disas_MsgBox from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/Disassembly_MsgBox.txt'
import Demo_MsgBox from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/Demo_MsgBox.mp4'
import ShellcodeExploit_Swap from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/ShellcodeExploit_Swap.txt'
import Disas_Swap from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/Disassembly_Swap.txt'
import Demo_Swap from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/Demo_Swap.mp4'
import ShellcodeExploit_Notepad from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Notepad.exe/ShellcodeExploit_Notepad.txt'
import Disas_Notepad from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Notepad.exe/Disassembly_Notepad.txt'
import Demo_Notepad from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Notepad.exe/Demo_Notepad.mp4'
import ShellcodeExploit_Calc from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Calc.exe/ShellcodeExploit_Calc.txt'
import Disas_Calc from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Calc.exe/Disassembly_Calc.txt'
import Demo_Calc from './Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Calc.exe/Demo_Calc.mp4'

function MinusSquare(props) {
    return (
        <VscFolderOpened />
    );
}

function PlusSquare(props) {
    return (
        <VscFolder />
    );
}

function CloseSquare(props) {
    return (
        <FiFileText />
    );
}

function TransitionComponent(props) {
    const style = useSpring({
        from: { opacity: 0, transform: 'translate3d(20px,0,0)' },
        to: { opacity: props.in ? 1 : 0, transform: `translate3d(${props.in ? 0 : 20}px,0,0)` },
    });

    return (
        <animated.div style={style}>
            <Collapse {...props} />
        </animated.div>
    );
}

TransitionComponent.propTypes = {
    /**
     * Show the component; triggers the enter or exit states
     */
    in: PropTypes.bool,
};

const StyledTreeItem = withStyles((theme) => ({
    iconContainer: {
        '& .close': {
            opacity: 0.3,
        },
    },
    group: {
        marginLeft: 7,
        paddingLeft: 18,
        borderLeft: `1px dashed ${fade(theme.palette.text.primary, 0.4)}`,
    },
}))((props) => <TreeItem {...props} TransitionComponent={TransitionComponent} />);

export default function CustomizedTreeView() {


    return (
        <div className="knowledgebase">
            <h2>Your journey begins..</h2>
            <TreeView
                className="tree"
                defaultCollapseIcon={<MinusSquare />}
                defaultExpandIcon={<PlusSquare />}
                defaultEndIcon={<CloseSquare />}
            >
                <a href={README1} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="0" label="0x001: README" /></a>
                <StyledTreeItem nodeId="1" label="0x100: Knowledge base">
                    <a href={Thesis} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="2" label="0x110: Author's Thesis" /></a>
                    <StyledTreeItem nodeId="3" label="0x120: Basics of Assembly">
                        <StyledTreeItem nodeId="7" label="0x121: Assembly Syntax">
                            <a href={SyntaxATnT} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="11" label="0x1211: AT&T Syntax" /></a>
                            <a href={SyntaxIntel} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="12" label="0x1212: Intel Syntax" /></a>
                        </StyledTreeItem>
                        <a href={AssmInstructions} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="8" label="0x122: Assembly Instructions" /></a>
                        <a href={EgInlineAssm} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="9" label="0x123: Example Inline Assembly Program" /></a>
                    </StyledTreeItem>
                    <StyledTreeItem nodeId="4" label="0x130: Background Reading Articles">
                        <a href="http://phrack.org/issues/49/14.html" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="5" label="0x131: Smashing the Stack for Fun and Profit - Aleph One" /></a>
                        <a href="http://flint.cs.yale.edu/cs421/papers/x86-asm/asm.html" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="51" label="0x132: x86 Assembly Guide (Comprehensive)" /></a>
                        <a href="https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="52" label="0x133: Windows Shellcode Development 1/3" /></a>
                        <a href="https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="53" label="0x134: Windows Shellcode Development 2/3" /></a>
                        <a href="https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="54" label="0x135: Windows Shellcode Development 3/3" /></a>
                    </StyledTreeItem>
                </StyledTreeItem>
                <StyledTreeItem nodeId="100" label="0x200: Programs">
                    <StyledTreeItem nodeId="105" label="0x210: By Author">
                        <a href={InlineAssm} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="106" label="0x211: Inline_Assembly.c" /></a>
                        <a href={SimpleProg} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="107" label="0x212: SimpleProg.c" /></a>
                        <a href={VulnerableProg} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="108" label="0x213: Vulnerable_Prog#1.c" /></a>
                        <a href={Shellcode_Basecode} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="109" label="0x214: Shellcode_Basecode.c" /></a>
                    </StyledTreeItem>
                    <StyledTreeItem nodeId="111" label="0x220: By Dr. Paul Evans">
                        <a href={Sender} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="112" label="0x221: Sender.c" /></a>
                        <a href={Receiver} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="113" label="0x222: Receiver.c" /></a>
                        <a href={Networked_Basecode} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="114" label="0x223: Networked_Basecode.c" /></a>
                    </StyledTreeItem>
                    <StyledTreeItem nodeId="115" label="0x230: By Steve Hanna">
                        <a href={arwin} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="116" label="0x231: Arwin.c" /></a>
                    </StyledTreeItem>
                </StyledTreeItem>
                <StyledTreeItem nodeId="200" label="0x300: Exploits">
                    <StyledTreeItem nodeId="211" label="0x310: Shellcode Exploits">
                        <StyledTreeItem nodeId="212" label="0x311: MessageBoxA">
                            <a href={ShellcodeExploit_MsgBox} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="213" label="0x3111: Shellcode Exploit" /></a>
                            <a href={Disas_MsgBox} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="214" label="0x3112: Disassembly" /></a>
                            <StyledTreeItem nodeId="215" label="0x3113: Demo - MessageBoxA"><div className="vplayer"><ReactPlayer
                                url={Demo_MsgBox}
                                width='100%'
                                height='100%'
                                controls={true}
                            /></div><br/></StyledTreeItem>
                        </StyledTreeItem>
                        <StyledTreeItem nodeId="216" label="0x312: SwapMouseButton" >
                            <a href={ShellcodeExploit_Swap} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="217" label="0x3121: Shellcode Exploit" /></a>
                            <a href={Disas_Swap} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="218" label="0x3122: Dissassembly" /></a>
                            <StyledTreeItem nodeId="219" label="0x3123: Demo - SwapMouseButton"><div className="vplayer"><ReactPlayer
                                url={Demo_Swap}
                                width='100%'
                                height='100%'
                                controls={true}
                            /></div><br/></StyledTreeItem>
                        </StyledTreeItem>
                        <StyledTreeItem nodeId="220" label="0x313: Calc.exe">
                            <a href={ShellcodeExploit_Calc} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="221" label="0x3131: Shellcode Exploit" /></a>
                            <a href={Disas_Calc} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="222" label="0x3132: Disassembly" /></a>
                            <StyledTreeItem nodeId="223" label="0x3133: Demo - Calc.exe"><div className="vplayer"><ReactPlayer
                                url={Demo_Calc}
                                width='100%'
                                height='100%'
                                controls={true}
                            /></div><br/></StyledTreeItem>
                        </StyledTreeItem>
                        <StyledTreeItem nodeId="230" label="0x314: Notepad.exe">
                            <a href={ShellcodeExploit_Notepad} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="231" label="0x3141: Shellcode Exploit" /></a>
                            <a href={Disas_Notepad} target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="232" label="0x3142: Disassembly" /></a>
                            <StyledTreeItem nodeId="233" label="0x3143: Demo - Notepad.exe"><div className="vplayer"><ReactPlayer
                                url={Demo_Notepad}
                                width='100%'
                                height='100%'
                                controls={true}
                            /></div><br/></StyledTreeItem>
                        </StyledTreeItem>
                    </StyledTreeItem>
                    <StyledTreeItem nodeId="240" label="0x320: Return-Oriented Programming">
                        <StyledTreeItem nodeId="241" label="0x321: Return-to-libc Exploit" />
                    </StyledTreeItem>
                </StyledTreeItem>
                <StyledTreeItem nodeId="300" label="0x400: Useful External Tools">
                    <a href="https://defuse.ca/online-x86-assembler.htm" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="301" label="0x410: x86/x64 Assembler and Disassembler" /></a>
                    <a href="https://www.rapidtables.com/convert/number/hex-to-ascii.html" target="_blank" rel="noopener noreferrer"><StyledTreeItem nodeId="302" label="0x420: Hex to ASCII Text Converter" /></a>
                </StyledTreeItem>
            </TreeView>
            <br />
        </div>
    );
}