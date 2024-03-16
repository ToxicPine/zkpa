import './App.css';
import FileUploader from './components/FileUploader';
import Header from './components/Header';

function App() {
  return (
    <div className="App">
      <div className="flex flex-col">
        <Header />
        <main className="flex-1">
          <FileUploader />
        </main>
      </div>
    </div>
  );
}

export default App;