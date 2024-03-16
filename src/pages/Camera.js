import React, { useRef, useState, useEffect } from 'react';

const Camera = () => {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const [capturedImageDataUrl, setCapturedImageDataUrl] = useState(null);
  const [isCameraRunning, setIsCameraRunning] = useState(false);
  const [stream, setStream] = useState(null); // To keep track of the media stream

  useEffect(() => {
    return () => {
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
      }
    };
  }, [stream]);

  const toggleCamera = () => {
    if (!isCameraRunning) {
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        navigator.mediaDevices.getUserMedia({ video: true })
          .then(stream => {
            setStream(stream);
            videoRef.current.srcObject = stream;
            videoRef.current.play();
            setIsCameraRunning(true);
          })
          .catch(err => {
            console.error("Error accessing the camera", err);
          });
      }
    } else {
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
        setIsCameraRunning(false);
      }
    }
  };

  const capturePhoto = () => {
    const context = canvasRef.current.getContext('2d');
    context.drawImage(videoRef.current, 0, 0, canvasRef.current.width, canvasRef.current.height);
    const imageDataUrl = canvasRef.current.toDataURL('image/png');
    setCapturedImageDataUrl(imageDataUrl);
  };

  return (
    <div className="text-white p-4 flex flex-col items-center">
      <div className="mb-4">
        <video ref={videoRef} className="max-w-full"></video>
        <button onClick={toggleCamera} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mr-2">
          {isCameraRunning ? 'Stop Camera' : 'Start Camera'}
        </button>
        <button onClick={capturePhoto} className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">Capture Photo</button>
      </div>
      {capturedImageDataUrl && (
        <div className="text-center">
          <h3 className="text-xl mb-2">Captured Image:</h3>
          <img src={capturedImageDataUrl} alt="Captured" className="max-w-full" />
        </div>
      )}
      <canvas ref={canvasRef} className="hidden" width="640" height="480"></canvas>
    </div>
  );
};

export default Camera;
