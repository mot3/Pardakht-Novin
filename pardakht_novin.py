from common.exceptions import PaymentReqError,ServerError


class PardakhtNovin:
    _BANK_BUY_TRANSACTION_TYPE = 'EN_GOODS'

    def __init__(
            self,
            invoice_id,
            amount, callback_url
    ) -> None:
        self.__sessionId = None
        self.__sign = False

        self.s_username = ""
        self.s_password = ""
        self.s_certificate_path = "./PardakhtNovin.pem"
        self.s_certificate_password = "PardakhtNovin@123456"

        self.invoice_id = invoice_id
        self.amount = amount
        self.callback_url = callback_url

    async def purchase(self):
        loginData = self.__getLoginData()
        response = await self.__callApi(self._getLoginUrl(), loginData)

        self.__sessionId = response['SessionId']

        if self.__sign:
            purchaseData = self._getSignPurchaseData()
            response = await self.__callApi(self._getSignPurchaseUrl(),
                                            purchaseData)

            dataToSign = response['DataToSign']
            dataUniqueId = response['UniqueId']

            signature = self.__getSignature(dataToSign)

            tokenGenerationData = {
                'WSContext': self.__getAuthData(),
                'Signature': signature,
                'UniqueId': dataUniqueId,
            }

            response = await self.__callApi(
                self._getTokenGenerationUrl(), tokenGenerationData)

        else:
            purchaseData = self._getNoSignPurchaseData()
            response = await self.__callApi(self._getNoSignPurchaseUrl(),
                                            purchaseData)

        self.token = response['Token']

        return self.token

    def pay(self):
        payUrl = self._getPaymentUrl()
        return payUrl+'?token='+self.token+'&lang=fa'

    @classmethod
    def instance_verify(cls, req_form):
        novin = cls(
            req_form['ResNum'],
            req_form['transactionAmount'], None)
        novin.token = req_form['token']
        novin.RefNum = req_form['RefNum']

        return novin

    async def verify(self):
        verificationData = self._getVerificationData()
        response = await self.__callApi(
            self._getVerificationUrl(),
            verificationData)
        
        if str(response['Amount']) == str(self.amount):
            return response

        raise PaymentReqError()

    def __getSignature(self, data_to_sign):
        with open(self.__getUnsignedDataFilePath(), 'w') as unsigned_file:
            unsigned_file.write(data_to_sign)

        # Creating an empty signed file
        with open(self.__getSignedDataFilePath(), 'w') as signed_file:
            signed_file.write('')

        # Signing the data using OpenSSL
        import subprocess

        openssl_command = [
            'openssl', 'smime', '-sign',
            '-in', self.__getUnsignedDataFilePath(),
            '-out', self.__getSignedDataFilePath(),
            '-signer', self.s_certificate_path,
            '-inkey', self.s_certificate_path,
            '-passin', 'pass:' + self.s_certificate_password
        ]

        subprocess.run(openssl_command)

        # Reading signed data
        with open(self.__getSignedDataFilePath(), 'r') as signed_file:
            signed_data = signed_file.read()

        # Extracting signed data
        signed_data_parts = signed_data.split('\n')
        return signed_data_parts[6]

    async def __callApi(self, url, data):
        headers = self.__getRequestHeaders()
        from aiohttp import ClientSession

        async with ClientSession() as client:
            response = await client.post(
                url,
                headers=headers,
                json=data)

        response = await response.json()

        if response['Result'] == 'erSucceed':
            return response

        raise ServerError(f'Unexpected error - {response}')

    def __getLoginData(self):

        return {
            "UserName": self.s_username,
            "Password": self.s_password
        }

    def __getAuthData(self):
        if self.__sessionId:
            return {
                'SessionId': self.__sessionId,
            }

        return {
            'UserId': self.s_username,
            'Password': self.s_password,
        }

    def _getNoSignPurchaseData(self):

        return {
            'WSContext': self.__getAuthData(),
            'TransType': self._BANK_BUY_TRANSACTION_TYPE,
            'ReserveNum': self.invoice_id,
            'Amount': self.amount,
            'RedirectUrl': self.callback_url,
        }

    def _getSignPurchaseData(self):

        return {
            'WSContext': self.__getAuthData(),
            'TransType': self._BANK_BUY_TRANSACTION_TYPE,
            'ReserveNum': self.invoice_id,
            'Amount': self.amount,
            'RedirectUrl': self.callback_url,
            # 'MobileNo': phoneNumber,
            # 'Email': self.email,
            # 'UserId': self.user_id,
        }

    def _getVerificationData(self):
        return {
            'WSContext': self.__getAuthData(),
            'Token': self.token,
            'RefNum': self.RefNum
        }

    def _getSuccessResponseStatusCode(self):
        return 'erSucceed'

    def _getLoginUrl(self):
        return self.__getBaseRestServiceUrl() + 'merchantLogin/'

    def _getNoSignPurchaseUrl(self):
        return self.__getBaseRestServiceUrl() + 'generateTokenWithNoSign/'

    def _getSignPurchaseUrl(self):
        return self.__getBaseRestServiceUrl() + 'generateTransactionDataToSign/'

    def _getTokenGenerationUrl(self):
        return self.__getBaseRestServiceUrl() + 'generateSignedDataToken/'

    def _getPaymentUrl(self):
        return 'https://pna.shaparak.ir/_ipgw_//payment/'

    def _getVerificationUrl(self):
        return self.__getBaseRestServiceUrl()+'verifyMerchantTrans/'

    def __getBaseRestServiceUrl(self):
        return 'https://pna.shaparak.ir/ref-payment2/RestServices/mts/'

    def __getRequestHeaders(self):
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def __getUnsignedDataFilePath(self):
        return './unsigned.txt'

    def __getSignedDataFilePath(self):
        return './signed.txt'