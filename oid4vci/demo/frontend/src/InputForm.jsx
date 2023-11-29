import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import "./InputForm.css"


const InputForm = () => {
  const navigate = useNavigate();
  const [firstName, setFirstName] = useState('Bob');
  const [lastName, setLastName] = useState('Builder');
  const [email, setEmail] = useState('bobthebuilder@professional.com');
  const [did, setDid] = useState('');
  const [credential, setCredential] = useState('');

  const handleFirstNameChange = (e) => {
    setFirstName(e.target.value);
  };

  const handleLastNameChange = (e) => {
    setLastName(e.target.value);
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
  };

  const handleCredentialChange = (e) => {
    setCredential(e.target.value);
  };

  const handleDidChange = (e) => {
    setDid(e.target.value);
  };

  const handleShareClick = () => {
    navigate(`/credentials`,{ state: {firstName:firstName, lastName:lastName, email:email, did:did, credential:credential}});
    
  };

 return (
    <div className="input-form-wrapper">
      <h2 className="input-form-title">OID4VCI Demo</h2>

      <div>
        <form className="input-form-form">
          <div>
            <label htmlFor="firstName" className="input-for-label">First Name:</label>
            <br />
            <input
              type="text"
              id="firstName"
              value={firstName}
              onChange={handleFirstNameChange}
              className="input-form-rectangle"
            />
          </div>

          <div>
            <label htmlFor="lastName" className="input-for-label">Last Name:</label>
            <br />
            <input
              type="text"
              id="lastName"
              value={lastName}
              onChange={handleLastNameChange}
              className="input-form-rectangle"
            />
          </div>

          <div>
            <label htmlFor="email" classname="input-for-label">Email:</label>
            <br />
            <input
              type="email"
              id="email"
              value={email}
              onChange={handleEmailChange}
              className="input-form-rectangle"
            />
          </div>

          <div>
            <label htmlFor="did" classname="input-for-label">Did:</label>
            <br />
            <input
              type="did"
              id="did"
              value={did}
              onChange={handleDidChange}
              className="input-form-rectangle"
            />
          </div>

          <div>
            <label htmlFor="credential" classname="input-for-label">Credential:</label>
            <br />
            <input
              type="credential"
              id="credential"
              value={credential}
              onChange={handleCredentialChange}
              className="input-form-rectangle"
            />
          </div>

          <div className="input-form-button-div">
            <button type="button" onClick={handleShareClick} className="input-form-button">
              Share
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default InputForm; 
