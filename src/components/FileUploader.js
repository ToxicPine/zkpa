import React, { useState, useRef } from 'react';
import { useDropzone } from 'react-dropzone';

const FileUploader = () => {
    const [file, setFile] = useState(null);
    const [progress, setProgress] = useState(0);
    const [importUrl, setImportUrl] = useState('');
    const [previewUrl, setPreviewUrl] = useState(null);

    const { getRootProps, getInputProps } = useDropzone({
        onDrop: (acceptedFiles) => {
            const newFile = acceptedFiles[0];
            setFile(newFile);
            setPreviewUrl(URL.createObjectURL(newFile));
        },
        accept: {
            'image/*': [],
        },
        maxSize: 25 * 1024 * 1024, // 25MB
    });

    const handleFileChange = (e) => {
        const newFile = e.target.files[0];
        setFile(newFile);
        setPreviewUrl(URL.createObjectURL(newFile));
    };

    const handleImportUrlChange = (e) => {
        setImportUrl(e.target.value);
    };

    const uploadFile = () => {
        if (file) {
            // 模拟上传进度
            const interval = setInterval(() => {
                setProgress((prevProgress) => {
                    const newProgress = prevProgress + 20;
                    if (newProgress >= 100) {
                        clearInterval(interval);
                    }
                    return newProgress;
                });
            }, 200);
        } else if (importUrl) {
            // 从 URL 导入图片
            fetch(importUrl)
                .then((response) => response.blob())
                .then((blob) => {
                    const newFile = new File([blob], 'imported-image.jpg', { type: 'image/jpeg' });
                    setFile(newFile);
                    setPreviewUrl(URL.createObjectURL(newFile));
                    // 模拟上传进度
                    const interval = setInterval(() => {
                        setProgress((prevProgress) => {
                            const newProgress = prevProgress + 20;
                            if (newProgress >= 100) {
                                clearInterval(interval);
                            }
                            return newProgress;
                        });
                    }, 200);
                })
                .catch((error) => {
                    console.error('Error importing image:', error);
                });
        }
    };

    const handleImportFromUrl = () => {
        uploadFile();
    };

    return (
        <div className="flex justify-center items-center h-screen bg-gray-800">
            <div className="bg-gray-700 rounded-lg p-8 w-2/3 max-w-4xl">
                <h2 className="text-2xl font-bold text-white mb-6">Upload Image</h2>
                <div
                    {...getRootProps()}
                    className="border-2 border-dashed border-gray-500 rounded-md p-8 mb-6"
                >
                    <input {...getInputProps()} />
                    {file || previewUrl ? (
                        <div>
                            <img
                                src={previewUrl}
                                alt={file?.name || 'Imported Image'}
                                className="max-h-64 mb-4 rounded-md"
                            />
                            <p className="text-white">{file?.name || 'Imported Image'}</p>
                            <progress
                                className="w-full bg-gray-500"
                                value={progress}
                                max="100"
                            ></progress>
                        </div>
                    ) : (
                        <p className="text-gray-400">Drag and Drop image here or Choose file</p>
                    )}
                </div>
                {!file && (
                    <label className="block mb-6">
                        <span className="sr-only">Choose file</span>
                        <input
                            type="file"
                            accept="image/*"
                            className="block w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-600 file:text-white hover:file:bg-gray-500"
                            onChange={handleFileChange}
                        />
                    </label>
                )}
                <hr className="my-6 border-gray-500" />
                <div className="mb-6">
                    <h3 className="text-xl font-bold text-white mb-2">Import from URL</h3>
                    <div className="flex">
                        <input
                            type="text"
                            placeholder="Enter image URL"
                            className="flex-grow bg-gray-600 text-white p-2 rounded-l-md focus:outline-none"
                            value={importUrl}
                            onChange={handleImportUrlChange}
                        />
                        <button
                            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-r-md"
                            onClick={handleImportFromUrl}
                        >
                            Import
                        </button>
                    </div>
                </div>
                <p className="text-gray-400 mb-6">Supported formats: Images</p>
                <p className="text-gray-400 mb-6">Maximum size: 25MB</p>
                <div className="flex justify-center">
                    <button
                        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                        onClick={uploadFile}
                        disabled={!file && !importUrl}
                    >
                        Upload
                    </button>
                </div>
            </div>
        </div>
    );
};

export default FileUploader;