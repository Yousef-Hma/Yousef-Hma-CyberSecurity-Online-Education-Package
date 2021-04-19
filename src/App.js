import Navbar from './Navbar.js';
import Home from './Home.js'
import {BrowserRouter as Router, Route, Switch} from 'react-router-dom'
import CodeReviewer from './CodeReviewer.js';
import NotFound from './NotFound.js';
import './index.css'
import { Container } from 'react-bootstrap';
import Footer from './Footer.js';
import KnowledgeBase from './KnowlegeBase.js';
import ShellcodeGenerator from './ShellcodeGenerator.js';

function App() {

  return (
    <Router>
    <div className="App">
    <Container style={{backgroundColor:'white'}}>
      <Navbar />
      <Switch>  
        <Route exact path="/">
          <Home/>
        </Route>
        <Route path="/knowledgebase">
          <KnowledgeBase/>
        </Route>
        <Route path="/codereviewer">
          <CodeReviewer/>
        </Route>
        <Route path="/shellcodegenerator">
          <ShellcodeGenerator/>
        </Route>
        <Route>
          <NotFound/>
        </Route>
      </Switch>
      <Footer />
      </Container>
      </div>
    </Router>
  );
}

export default App;
