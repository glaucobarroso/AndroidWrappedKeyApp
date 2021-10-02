package com.sample.wrappedkey.services

import com.sample.wrappedkey.payload.DeviceInfo
import com.sample.wrappedkey.payload.WrappedKey
import retrofit2.Call
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

interface KeyService {

    @Headers("Content-Type: application/json")
    @POST("getWrappedKey")
    fun getWrappedKey(@Body deviceInfo: DeviceInfo): Call<WrappedKey>
}