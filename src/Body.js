import { Link } from "react-router-dom";
import Thesis from './Attachments/Thesis.pdf'

const Body = () => {

    return ( 
        <div className="body">
            <h3>Introduction</h3>
            <p>Welcome to your cybersecurity educational package. This package is designed to guide you through the basics of memory-corruption vulnerabilities and their various exploits. Included with this package are 2 tools:<p><br/><b><a href="/ShellcodeGenerator" > - Shellcode Generator</a><br/><a href="/CodeReviewer" >- Code Reviewer</a></b></p></p>
            <h3>First thing's first</h3>
            <p>Seeing that this is a rather technical topic, some background knowledge is required. My recommendation would be to start by reading the <i><a href={'Thesis'} > Author's Thesis </a></i> as it provides a complete overview and is on its own enough to get you started.</p>
            <p>However, I do understand that not all users of this site would want to go through the trouble of reading a 60-page document, so I have provided additonal links in the <b>Related Articles</b> section, found in the top navigation bar, that I personally found very insightful.</p>
            <p>Furthermore, there has been an attempt to make the educational package as detailed/documented as possible with several supporting examples and programs to make the learning process as straight forward as possible should you wish to dive right in without doing any background reading.</p>
            <h3>Disclaimer</h3>
            <p>A person with a background in Cybersecurity should know better than to download shellcode exploits from online sources, and although every effort has been made to ensure complete transparency in what each shellcode does, I still <b>highly</b> recommend watching the demo videos attached rather than executing it on your own device.</p>
            <p><b>NB:</b> None of the exploits provided in this package perform actions of malicous nature, but rather they perform simple and reversible actions such as launching an app or conveying a message. However, if you choose to copy the shellcodes provided I will not be held responsible for any negative impact it may result in on your device.</p>
            <p style={{textAlign:'center'}}><b> You have been warned! </b></p>
        </div>
     );
}
 
export default Body;