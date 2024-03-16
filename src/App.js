import './App.css';
import FileUploader from './components/FileUploader';
import Header from './components/Header';
import Share from './components/Share';

function App() {
  return (
    <div className="App">
      <div className="flex flex-col">
        <Header />
        <main className="flex-1">
          <FileUploader />
        </main>
        <Share />
      </div>
    </div>
  );
}

export default App;