import React, { useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import CloseIcon from '@mui/icons-material/Close';
import FileCopyIcon from '@mui/icons-material/FileCopy';
import uploadAnimation from '../assets/upload-animation.gif';

const FileUploader = () => {
    const [file, setFile] = useState(null);
    const [previewUrl, setPreviewUrl] = useState(null);
    const [importUrl, setImportUrl] = useState('');
    const [hash, setHash] = useState(null);
    const [hashByteArray, setHashByteArray] = useState(null);
    const [copySuccess, setCopySuccess] = useState('');
    const [showAnimatedPreview, setShowAnimatedPreview] = useState(false);

    const { getRootProps, getInputProps } = useDropzone({
        onDrop: (acceptedFiles) => {
            const newFile = acceptedFiles[0];
            setFile(newFile);
            setPreviewUrl(URL.createObjectURL(newFile));
            setShowAnimatedPreview(true);
            handleImageUpload(newFile);
        },
        accept: {
            'image/*': [],
        },
        maxSize: 25 * 1024 * 1024, // 25MB
    });

    useEffect(() => {
        let timeoutId;
        if (showAnimatedPreview) {
            timeoutId = setTimeout(() => {
                setShowAnimatedPreview(false);
            }, 2100);
        }
        return () => clearTimeout(timeoutId);
    }, [showAnimatedPreview]);

    const handleFileChange = (e) => {
        const newFile = e.target.files[0];
        setFile(newFile);
        setPreviewUrl(URL.createObjectURL(newFile));
        setShowAnimatedPreview(true);
        handleImageUpload(newFile);
    };

    const handleImportFromUrl = () => {
        fetchImageFromUrl(importUrl);
    };

    const fetchImageFromUrl = async (url) => {
        try {
            setPreviewUrl(url);
            const response = await fetch(url, {
                mode: 'no-cors'
            });
            const blob = await response.blob();
            const newFile = new File([blob], 'imported-image.jpg', { type: 'image/jpeg' });
            setFile(newFile);
            setShowAnimatedPreview(true);
            handleImageUpload(newFile);
        } catch (error) {
            console.error('Error importing image:', error);
        }
    };

    const handleImageUpload = async (file) => {
        try {
            const formData = new FormData();
            formData.append('image', file);
            const response = await fetch('/hash_image', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error uploading image:', errorText);
                return;
            }

            const data = await response.json();
            console.log('Response data:', data);
            setHash(data.hash_hex);
            setHashByteArray(data.hash_byte_array);
        } catch (error) {
            console.error('Error uploading image:', error);
        }
    };

    const copyToClipboard = () => {
        navigator.clipboard.writeText(hash)
            .then(() => {
                setCopySuccess('Copied!');
                setTimeout(() => setCopySuccess(''), 2000); // Remove the success message after 2 seconds
            })
            .catch((err) => {
                console.error('Could not copy text: ', err);
            });
    };

    const handleVerify = () => {
        // 在这里添加验证逻辑
        console.log('Verifying image...');
    };

    const handleReset = () => {
        setFile(null);
        setPreviewUrl(null);
        setImportUrl('');
        setHash(null);
        setHashByteArray(null);
        setShowAnimatedPreview(false);
    };

    return (
        <div className="flex justify-center items-center h-screen bg-black">
            <div className="bg-black rounded-lg p-8 w-1/2 max-w-4xl">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-2xl font-bold text-white">Upload Image</h2>
                    {(file || previewUrl) && (
                        <button
                            className="text-gray-400 hover:text-white transition-colors duration-300"
                            onClick={handleReset}
                        >
                            <CloseIcon />
                        </button>
                    )}
                </div>
                <div
                    {...getRootProps()}
                    className="border-2 border-dashed border-gray-500 rounded-md p-8 mb-6 h-80 flex flex-col justify-center items-center hover:bg-gray-800 transition-colors duration-300"
                >
                    <input {...getInputProps()} />
                    {file || previewUrl ? (
                        <div>
                            {showAnimatedPreview ? (
                                <img
                                    src={uploadAnimation}
                                    alt={file?.name || 'Imported Image'}
                                    className="max-h-64 mb-4 rounded-md mx-auto"
                                />
                            ) : (
                                <img
                                    src={previewUrl}
                                    alt={file?.name || 'Imported Image'}
                                    className="max-h-64 mb-4 rounded-md mx-auto"
                                />
                            )}
                            <p className="text-white text-center">{file?.name || 'Imported Image'}</p>

                            {/* {hashByteArray && (
                                <p className="text-white text-center">
                                    Hash Byte Array: [{hashByteArray}]
                                </p>
                            )} */}
                        </div>
                    ) : (
                        <>
                            <CloudUploadIcon fontSize="large" color="primary" />
                            <p className="text-gray-400">Drag and Drop image here or Choose file</p>
                            <label className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-md mt-4 cursor-pointer transition-colors duration-300">
                                <input
                                    type="file"
                                    accept="image/*"
                                    className="sr-only"
                                    onChange={handleFileChange}
                                />
                                Upload
                            </label>
                        </>
                    )}
                </div>
                {hash && (
                    <div className="flex items-center justify-between bg-gray-800 p-3 rounded-md">
                        <span className="text-gray-300 mr-2">Hash of Image </span>
                        <div className="flex items-center space-x-3">
                            <p className="text-gray-300 text-center truncate">
                                {hash.substring(0, 15)}.....{hash.slice(-15)}
                            </p>
                            <button
                                onClick={copyToClipboard}
                                className="flex items-center text-gray-300 hover:text-white transition-colors duration-300"
                            >
                                <FileCopyIcon fontSize="small" />
                                <span className="ml-1">Copy</span>
                            </button>
                        </div>
                    </div>
                )}
                {!file && !previewUrl && (
                    <>
                        <hr className="my-6 border-gray-500" />
                        <div className="flex justify-between w-full px-6 mb-6">
                            <p className="text-gray-400">Supported formats: Images</p>
                            <p className="text-gray-400">Maximum size: 25MB</p>
                        </div>
                        <div className="mb-6">
                            <h3 className="text-xl font-bold text-white mb-2 text-left">Import from URL</h3>
                            <div className="flex">
                                <input
                                    type="text"
                                    placeholder="Enter image URL"
                                    className="flex-grow bg-gray-600 text-white p-2 rounded-l-md focus:outline-none"
                                    value={importUrl}
                                    onChange={(e) => setImportUrl(e.target.value)}
                                />
                                <button
                                    className="bg-gray-500 text-white font-bold py-2 px-4 rounded-r-md hover:bg-gray-600 transition-colors duration-300"
                                    onClick={() => handleImportFromUrl()}
                                >
                                    Import
                                </button>
                            </div>
                        </div>

                    </>
                )}
                {file || previewUrl ? (
                    <div className="flex justify-end mt-6">
                        <button
                            className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded-md mr-4 transition-colors duration-300"
                            onClick={handleVerify}
                        >
                            Verify
                        </button>
                        <button
                            className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-md transition-colors duration-300"
                            onClick={handleReset}
                        >
                            Reset
                        </button>
                    </div>
                ) : null}
            </div>
        </div>
    );
};

export default FileUploader;