import { useState } from "react";
// import { useHistory } from 'react-router-dom';

const CodeReviewer = () => {
const [body, setBody] = useState('');
const [strcpys, setStrcpys]= useState(0);
const [getss, setGetss]= useState(0);
const [scanfs, setScanfs]= useState(0);
const [strcats, setStrcats]= useState(0);
const [memcpys, setMemcpys]= useState(0);
const [memmoves, setMemoves]= useState(0);
const [freads, setFreads]= useState(0);
const [printfs, setPrintfs]= useState(0);
const [sprintfs, setSprintfs]= useState(0);
const [isPending, setIsPending] = useState(false);

function countOccurences(string, word) {
    return string.split(word).length - 1;
 }

const handleSubmit = (e) => {
    e.preventDefault();
    console.log('in')
    setIsPending(true);

    /* Scan for vulnerabilities */
   setSprintfs(countOccurences(body, "sprintf("))
   setStrcpys(countOccurences(body, "strcpy("))
   setGetss(countOccurences(body, "gets("))
   setScanfs(countOccurences(body, "scanf("))
   setStrcats(countOccurences(body, "strcat("))
   setMemcpys(countOccurences(body, "memcpy("))
   setMemoves(countOccurences(body, "memmove("))
   setFreads(countOccurences(body, "fread("))
   setPrintfs(countOccurences(body, "printf("))
   
   
   setIsPending(false)
}

    return (  
        <div className="codereviewer">
            <h6><br/><b style={{color:"#242582"}}>Code Reviewer</b></h6>
            <form onSubmit={handleSubmit}>
                <div className="box">
                <div className="pull-left">
                <label>Insert code:</label>
                <textarea className="numbered"
                required
                value={body}
                placeholder="Your code.."
                onChange ={(e) => setBody(e.target.value)}
                ></textarea>
                {!isPending && <button className="centerbtn">Scan code</button>}
                {isPending && <button className="centerbtn" disabled>Scanning...</button>}
                </div>
                <div className="pull-right">
                <label style={{ paddingRight:"0vw"}}>Vulnerability Report:</label>
                <div className="report">
                {!isPending && <p style={{textAlign:"center", paddingTop: "3%"}}><b>{strcpys + getss + scanfs + strcats + memcpys + memmoves + freads + (printfs-sprintfs) + sprintfs}</b> memory-corruption vulnerabilities found.</p>}
                {strcpys!==0 && <p><b><i>strcpy(dest,src)</i></b> is present <b>{strcpys}</b> times.</p>}
                {getss!==0 && <p><i><b>gets(input)</b></i> is present <b>{getss}</b> times.</p>}
                {scanfs!==0 && <p><i><b>scanf(input)</b></i> is present <b>{scanfs}</b> times.</p>}
                {strcats!==0 && <p><i><b>strcat(dest,src)</b></i> is present <b>{strcats}</b> times.</p>}
                {memcpys!==0 &&<p><i><b>memcpy(dest,src, size)</b></i> is present <b>{memcpys}</b> times.</p>}
                {memmoves!==0 &&<p><i><b>memmove(str1, str2, size)</b></i> is present <b>{memmoves}</b> times.</p>}
                {freads!==0 &&<p><i><b>fread(file_input)</b></i> is present <b>{freads}</b> times.</p>}
                {printfs!==0 &&<p><i><b>printf(output)</b></i> is present <b>{printfs - sprintfs}</b> times.</p>}
                {sprintfs!==0 &&<p><i><b>sprintf(output)</b></i> is present <b>{sprintfs}</b> times.</p>}
                </div>
                </div>
                </div>
                {/* <label>Blog author:</label>
                <select
                    value = {author}
                    onChange ={(e) => setAuthor(e.target.value)}
                >
                    <option value="mario">mario</option>
                    <option value="yoshi">yoshi</option>
                </select> */}
                <br/>
            </form>
        </div>
    );
}
 
export default CodeReviewer;