import React, { useRef, useState, useEffect } from 'react';
import { saveAs } from 'file-saver';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { SuccessDialog, WaitDialog } from '../components/Modal';
// import { generateProof } from '../proof/zkpa';

const Camera = () => {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const [isCameraRunning, setIsCameraRunning] = useState(false);
  const [stream, setStream] = useState(null);
  const [isImageCaptured, setIsImageCaptured] = useState(false);
  const [isWaitOpen, setIsWaitOpen] = useState(false);
  const [isSuccessOpen, setIsSuccessOpen] = useState(false);

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
            setIsImageCaptured(false);
          })
          .catch(err => {
            console.error("Error accessing the camera", err);
          });
      }
    } else {
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
        setIsCameraRunning(false);
        setIsImageCaptured(false);
      }
    }
  };

  const capturePhoto = async () => {
    setIsImageCaptured(true);
    setIsWaitOpen(true);

    if (stream) {
      stream.getTracks().forEach(track => track.stop());
      setIsCameraRunning(false);
    }

    const context = canvasRef.current.getContext('2d');
    context.drawImage(videoRef.current, 0, 0, canvasRef.current.width, canvasRef.current.height);
    canvasRef.current.toBlob(async (blob) => {
      const formData = new FormData();
      formData.append('image', blob, 'image.png');

      try {
        const response = await fetch('https://image-hash-browser.vercel.app/get_witness', {
          method: 'POST',
          body: formData
        });

        if (response.ok) {
          console.log('Witness data fetched successfully');
        } else {
          console.error('Error sending image');
        }
        // eslint-disable-next-line
        const data = await response.json();
        setTimeout(() => {
          setIsWaitOpen(false);
          setIsSuccessOpen(true);
          setTimeout(() => {
            downloadImage();
          }, 2000)

        }, 3000)
        // generateProofByWitness(data);
      } catch (error) {
        console.error('Error sending image:', error);
        setIsWaitOpen(false);
        toast.error("Something wrong during fetching witness data of image")
      }
    }, 'image/png');
  };

  // const generateProofByWitness = async (data) => {
  //   try {
  //     console.log("In function of generateProofByWitness ")
  //     // const proof = await generateProof(data);
  //     console.log("Proof:", proof);
  //   } catch (error) {
  //     console.log("Error in generating proof");
  //   }
  // }

  const downloadImage = () => {
    const context = canvasRef.current.getContext('2d');
    context.drawImage(videoRef.current, 0, 0, canvasRef.current.width, canvasRef.current.height);
    canvasRef.current.toBlob(blob => {
      saveAs(blob, "web-image.png");
      toast.success("Image captured successfully! You can download.");
    }, 'image/png');
  }

  return (
    <div className="text-white p-4 flex flex-col items-center">
      <ToastContainer position="bottom-right" />
      <SuccessDialog open={isSuccessOpen} onClose={() => { setIsSuccessOpen(false) }} title={'Success'} message={'The image was signed successfully. Download automatically soon.'} />
      <WaitDialog open={isWaitOpen} onClose={() => setIsWaitOpen(false)} />
      <div className="bg-gray-200 border-2 border-gray-400 max-w-full" style={{ width: '640px', height: '480px', backgroundColor: 'black' }}>
        <video ref={videoRef} className="max-w-full" style={{ display: isImageCaptured ? 'none' : 'block' }}></video>
        <canvas ref={canvasRef} className={`max-w-full ${!isImageCaptured ? 'bg-gray-300' : ''}`} width="640" height="480" style={{ display: isImageCaptured ? 'block' : 'none' }}></canvas>
      </div>
      <div className="flex justify-center mt-4">
        {!isImageCaptured && (
          <button onClick={toggleCamera} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
            {isCameraRunning ? 'Stop Camera' : 'Start Camera'}
          </button>
        )}
        {isCameraRunning && !isImageCaptured && (
          <button onClick={capturePhoto} className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded ml-2">
            Capture Photo
          </button>
        )}
        {isImageCaptured && (
          <button onClick={toggleCamera} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
            Retake Photo
          </button>
        )}
      </div>
    </div>
  );
};

export default Camera;
