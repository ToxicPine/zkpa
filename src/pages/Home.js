import React from 'react';

import FileUploader from '../components/FileUploader';
import Share from '../components/Share';

function Home() {
  return (
    <div className="flex flex-col">
      <main className="flex-1">
        <FileUploader />
      </main>
      <Share />
    </div>
  )
}

export default Home;