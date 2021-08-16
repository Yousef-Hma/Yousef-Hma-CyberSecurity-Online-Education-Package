import Body from './Body';
import gif from './Attachments/EDU_CS.gif';

const Home = () => {


    return (
        <div className="home">
            <img src={gif} className="center" alt="CS gif"/>
            {/* {<div style={{textAlign:'center'}}><br/> Loading... <br/><br/></div>} */}
            {<Body/>}
        </div>
    );
}

export default Home;