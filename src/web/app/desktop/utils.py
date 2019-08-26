from phoenix.cloud import image as OpenstackImageService
from phoenix.cloud import compute as OpenstackComputeService
from phoenix.cloud import network as OpenstackNetworkService


def list_of_image():
    image_list = []
    for image in OpenstackImageService.list_images():
        image_list.append(image)
    return image_list


def list_of_flavor():
    flavor_list = []
    for flavor in OpenstackComputeService.list_flavors():
        flavor_list.append(flavor)
    return flavor_list


def list_of_network():
