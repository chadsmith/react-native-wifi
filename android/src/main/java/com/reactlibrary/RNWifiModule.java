package com.reactlibrary;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.provider.Settings;

import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.util.List;

public class RNWifiModule extends ReactContextBaseJavaModule implements LifecycleEventListener {

	private WifiManager wifiManager;
	private ConnectivityManager connectivityManager;
	private ReactApplicationContext context;
	private ConnectivityManager.NetworkCallback networkCallback;

	RNWifiModule(ReactApplicationContext reactContext) {
		super(reactContext);
		wifiManager = (WifiManager) reactContext.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
		connectivityManager = (ConnectivityManager) reactContext.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
		context = getReactApplicationContext();
	}

	@Override
	public String getName() {
		return "WifiManager";
	}


	//Method to force wifi usage if the user needs to send requests via wifi
	//if it does not have internet connection. Useful for IoT applications, when
	//the app needs to communicate and send requests to a device that have no
	//internet connection via wifi.
	private void forceWifiUsage(boolean useWifi, final String ssid) {
		boolean canWriteFlag = false;

		if (useWifi) {
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {

				if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
					canWriteFlag = true;
					// Only need ACTION_MANAGE_WRITE_SETTINGS on 6.0.0, regular permissions suffice on later versions
				} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
					canWriteFlag = Settings.System.canWrite(context);

					if (!canWriteFlag) {
						Intent intent = new Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS);
						intent.setData(Uri.parse("package:" + context.getPackageName()));
						intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

						context.startActivity(intent);
					}
				}

				if (!(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) || canWriteFlag) {

					NetworkRequest.Builder builder = new NetworkRequest.Builder();
					builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);

					if(networkCallback != null)
						connectivityManager.unregisterNetworkCallback(networkCallback);

					networkCallback = new ConnectivityManager.NetworkCallback() {
						@Override
						public void onAvailable(Network network) {
							boolean bound = false;
							if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
								connectivityManager.bindProcessToNetwork(null);
								if (ssid == null || getSSID().equals(ssid))
									bound = connectivityManager.bindProcessToNetwork(network);
							} else {
								// This method was deprecated in API level 23
								ConnectivityManager.setProcessDefaultNetwork(null);
								if (ssid == null || getSSID().equals(ssid))
									bound = ConnectivityManager.setProcessDefaultNetwork(network);
							}
							if(bound) {
								connectivityManager.unregisterNetworkCallback(this);
								networkCallback = null;
							}
						}
					};

					connectivityManager.requestNetwork(builder.build(), networkCallback);
				}
			}
		} else {
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
				connectivityManager.bindProcessToNetwork(null);
			} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
				ConnectivityManager.setProcessDefaultNetwork(null);
			}
		}
	}

	private Boolean connectTo(String ssid, String password) {
		WifiConfiguration conf = new WifiConfiguration();

		conf.allowedAuthAlgorithms.clear();
		conf.allowedGroupCiphers.clear();
		conf.allowedKeyManagement.clear();
		conf.allowedPairwiseCiphers.clear();
		conf.allowedProtocols.clear();

		conf.SSID = String.format("\"%s\"", ssid);

		if (password != null && !password.isEmpty()) {
			conf.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

			conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
			conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);

			conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);

			conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
			conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

			conf.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
			conf.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
			conf.status = WifiConfiguration.Status.ENABLED;
			conf.preSharedKey = String.format("\"%s\"", password);
		} else {
			conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
		}

		if (!wifiManager.isWifiEnabled())
			wifiManager.setWifiEnabled(true);

		int networkId = -1;

		List<WifiConfiguration> mWifiConfigList = wifiManager.getConfiguredNetworks();
		if (mWifiConfigList != null) {
			for (WifiConfiguration wifiConfig : mWifiConfigList) {
				if (wifiConfig.SSID.equals(conf.SSID)) {
					conf = wifiConfig;
					networkId = conf.networkId;
				}
			}
		}

		// Use the existing network config if exists

		// If network not already in configured networks add new network
		if ( networkId == -1 ) {
			networkId = wifiManager.addNetwork(conf);
			wifiManager.saveConfiguration();
		}

		// if network not added return false
		if ( networkId == -1 ) {
			return false;
		}

		// disconnect current network
		boolean disconnect = wifiManager.disconnect();

		if ( !disconnect ) {
			return false;
		}

		// enable new network
		return wifiManager.enableNetwork(networkId, true);
	}

	private String getSSID() {
		WifiInfo info = wifiManager.getConnectionInfo();

		// This value should be wrapped in double quotes, so we need to unwrap it.
		String ssid = info.getSSID();
		NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();

		if ((ssid == null || ssid.equals("<unknown ssid>")) && networkInfo != null)
			ssid = networkInfo.getExtraInfo();

		if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\""))
			ssid = ssid.substring(1, ssid.length() - 1);

		if(info.getSupplicantState() == SupplicantState.COMPLETED)
			return ssid;
		return "";
	}

	private void removeSsid(String ssid) {
		List<WifiConfiguration> configList = wifiManager.getConfiguredNetworks();
		String comparableSSID = ('"' + ssid + '"');

		if (configList != null) {
			for (WifiConfiguration wifiConfig : configList) {
				if (wifiConfig.SSID.equals(comparableSSID)) {
					int networkId = wifiConfig.networkId;
					wifiManager.removeNetwork(networkId);
					wifiManager.saveConfiguration();
				}
			}
		}
	}

	@ReactMethod
	public void connectToSSID(String ssid, Promise promise) {
		Boolean enabled = connectTo(ssid, "");
		if(enabled) {
			forceWifiUsage(true, ssid);
			promise.resolve(true);
		}
		else
			promise.reject(new Throwable("unable to connect to network: " + ssid));
	}

	@ReactMethod
	public void connectToProtectedSSID(String ssid, String password, Promise promise) {
		Boolean enabled = connectTo(ssid, password);
		if(enabled) {
			forceWifiUsage(true, ssid);
			promise.resolve(true);
		}
		else
			promise.reject(new Throwable("unable to connect to network: " + ssid));
	}

	@ReactMethod
	public void getCurrentWifiSSID(Promise promise) {
		String ssid = getSSID();
		promise.resolve(ssid);
	}

	@ReactMethod
	public void disconnectFromSSID(String ssid, Promise promise) {
		boolean disconnect = wifiManager.disconnect();

		if ( !disconnect ) {
			promise.resolve(false);
			return;
		}

		forceWifiUsage(false, ssid);
		removeSsid(ssid);
		promise.resolve(true);
	}

	@Override
	public void onHostResume() {

	}

	@Override
	public void onHostPause() {

	}

	@Override
	public void onHostDestroy() {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && networkCallback != null) {
			connectivityManager.unregisterNetworkCallback(networkCallback);
		}
	}
}
